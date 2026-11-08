// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! `--correlate --json` on calls that share an SDP origin, through the shipped
//! binary.
//!
//! A B2BUA that passes the offer through is an `sdp_origin` identifier match at
//! score 90. Calls that reuse one origin, as SIPp's built-in `uac` scenario
//! does, are not. The rule is in `src/sip/sdp_origin.rs`.
//!
//! The captures are built here, deterministically, from RFC 5737 addresses and
//! `example.com` names. `harness/th-callid/capture.sh` cannot build them: it
//! needs Docker, an OpenSIPS image and SIPp, its timestamps are the wall clock,
//! and its own scenarios write a distinct origin per call.

#![cfg(all(unix, feature = "full"))]

#[path = "support/pcap_build.rs"]
mod pcap_build;
#[path = "support/surface_parity.rs"]
mod surface_parity;
#[path = "../src/test_scratch.rs"]
mod test_scratch;

use pcap_build::{udp_frame, write_pcap_at};
use surface_parity::run_cli;
use test_scratch::ScratchDir;

type TestError = Box<dyn std::error::Error>;

/// The origin SIPp's built-in `uac` scenario writes into every call.
const SIPP_ORIGIN: &str = "user1 53655765 2353687637 IN IP4 192.0.2.1";
/// An origin written once, for one session.
const ORIGIN: &str = "alice 2890844526 2890842807 IN IP4 192.0.2.1";

/// The caller.
const UAC: [u8; 4] = [192, 0, 2, 1];
/// The proxy or B2BUA.
const SBC: [u8; 4] = [192, 0, 2, 10];
/// The callee.
const UAS: [u8; 4] = [198, 51, 100, 30];

/// One leg: an INVITE with `origin` from `src` to `dst` at `start`
/// microseconds, and a 200 OK back at `end`.
fn leg(
    call_id: &str,
    src: [u8; 4],
    dst: [u8; 4],
    origin: &str,
    start: u64,
    end: u64,
) -> Vec<(Vec<u8>, u64)> {
    let sdp = format!(
        "v=0\r\no={origin}\r\ns=-\r\nc=IN IP4 198.51.100.7\r\nt=0 0\r\n\
         m=audio 40000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n"
    );
    let (from, to) = (std::net::Ipv4Addr::from(src), std::net::Ipv4Addr::from(dst));
    let invite = format!(
        "INVITE sip:bob@example.com SIP/2.0\r\n\
         Via: SIP/2.0/UDP {from}:5060;branch=z9hG4bK-{call_id}\r\n\
         Max-Forwards: 70\r\n\
         From: <sip:alice@example.com>;tag=f-{call_id}\r\n\
         To: <sip:bob@example.com>\r\n\
         Call-ID: {call_id}\r\n\
         CSeq: 1 INVITE\r\n\
         Contact: <sip:alice@{from}:5060>\r\n\
         Content-Type: application/sdp\r\n\
         Content-Length: {}\r\n\r\n{sdp}",
        sdp.len()
    );
    let ok = format!(
        "SIP/2.0 200 OK\r\n\
         Via: SIP/2.0/UDP {from}:5060;branch=z9hG4bK-{call_id}\r\n\
         From: <sip:alice@example.com>;tag=f-{call_id}\r\n\
         To: <sip:bob@example.com>;tag=t-{call_id}\r\n\
         Call-ID: {call_id}\r\n\
         CSeq: 1 INVITE\r\n\
         Contact: <sip:bob@{to}:5060>\r\n\
         Content-Length: 0\r\n\r\n"
    );
    vec![
        (udp_frame(src, dst, 5060, 5060, invite.as_bytes()), start),
        (udp_frame(dst, src, 5060, 5060, ok.as_bytes()), end),
    ]
}

/// Write `legs` to `name` in a fresh scratch directory, frames in time order.
fn capture(name: &str, legs: Vec<Vec<(Vec<u8>, u64)>>) -> Result<(ScratchDir, String), TestError> {
    let dir = ScratchDir::new("sipnab-sdp-origin-")?;
    let path = dir.join(name);
    let mut frames: Vec<(Vec<u8>, u64)> = legs.into_iter().flatten().collect();
    frames.sort_by_key(|(_, t)| *t);
    write_pcap_at(&path, &frames, 1)?;
    let path = path.to_str().ok_or("a UTF-8 path")?.to_string();
    Ok((dir, path))
}

/// `--correlate <call_id> --json` against `pcap`, as the parsed answer.
fn correlate(pcap: &str, call_id: &str) -> Result<serde_json::Value, TestError> {
    let run = run_cli(
        pcap,
        &[
            "--correlate",
            call_id,
            "--json",
            "--no-cli-print",
            "--quiet",
        ],
    )?;
    assert_eq!(run.code, Some(0), "stderr:\n{}", run.stderr);
    run.last_json()
}

/// The legs of `answer` as (Call-ID, strategy, identifier_match, score).
fn legs(answer: &serde_json::Value) -> Vec<(String, String, bool, u64)> {
    let mut v: Vec<(String, String, bool, u64)> = answer["legs"]
        .as_array()
        .map(|legs| {
            legs.iter()
                .map(|l| {
                    (
                        l["call_id"].as_str().unwrap_or_default().to_string(),
                        l["strategy"].as_str().unwrap_or_default().to_string(),
                        l["identifier_match"].as_bool().unwrap_or_default(),
                        l["score"].as_u64().unwrap_or_default(),
                    )
                })
                .collect()
        })
        .unwrap_or_default();
    v.sort();
    v
}

/// The legs of `answer` that `sdp_origin` matched.
fn origin_legs(answer: &serde_json::Value) -> Vec<String> {
    legs(answer)
        .into_iter()
        .filter(|(_, s, _, _)| s == "sdp_origin")
        .map(|(id, _, _, _)| id)
        .collect()
}

/// The A and B legs of one call through a B2BUA that passed `origin` through.
fn passthrough(origin: &str) -> Vec<Vec<(Vec<u8>, u64)>> {
    vec![
        leg("a@example.com", UAC, SBC, origin, 0, 900_000),
        leg("b@example.com", SBC, UAS, origin, 2_000, 890_000),
    ]
}

/// Three SIPp calls through a proxy, one second apart, all with SIPp's origin:
/// the reproduction of the defect.
fn sipp_sequential() -> Vec<Vec<(Vec<u8>, u64)>> {
    (0..3_u64)
        .flat_map(|n| {
            let start = n * 1_000_000;
            [
                leg(
                    &format!("{}-th-call@example.com", n + 1),
                    UAC,
                    SBC,
                    SIPP_ORIGIN,
                    start,
                    start + 600_000,
                ),
                leg(
                    &format!("{}-th-call-b@example.com", n + 1),
                    SBC,
                    UAS,
                    SIPP_ORIGIN,
                    start + 1_000,
                    start + 599_000,
                ),
            ]
        })
        .collect()
}

#[test]
fn a_b2bua_passing_the_offer_through_is_an_identifier_match() -> Result<(), TestError> {
    let (_dir, pcap) = capture("passthrough.pcap", passthrough(ORIGIN))?;
    let answer = correlate(&pcap, "a@example.com")?;
    assert_eq!(
        legs(&answer),
        vec![(
            "b@example.com".to_string(),
            "sdp_origin".to_string(),
            true,
            90
        )],
        "{answer}"
    );
    assert_eq!(answer["heuristic_only"], false, "{answer}");
    assert_eq!(answer["legs"][0]["method"], "sdp", "{answer}");
    assert_eq!(
        answer["legs"][0]["observed_gap_ms"],
        serde_json::Value::Null,
        "a b2bua passing the offer through is an identifier match"
    );
    Ok(())
}

/// The table labels an origin match an identifier, with no gap, and does not
/// call the answer a guess.
#[test]
fn the_table_labels_an_origin_match_an_identifier() -> Result<(), TestError> {
    let (_dir, pcap) = capture("passthrough.pcap", passthrough(ORIGIN))?;
    let run = run_cli(
        &pcap,
        &["--correlate", "a@example.com", "--no-cli-print", "--quiet"],
    )?;
    assert_eq!(run.code, Some(0), "stderr:\n{}", run.stderr);
    let row: Vec<&str> = run
        .stdout
        .lines()
        .find(|l| l.starts_with("b@example.com"))
        .ok_or("the leg row")?
        .split_whitespace()
        .collect();
    assert_eq!(
        row,
        vec![
            "b@example.com",
            "sdp_origin",
            "sdp",
            "90",
            "identifier",
            "-",
            "-"
        ],
        "{}",
        run.stdout
    );
    assert!(!run.stdout.contains("timing guess"), "{}", run.stdout);
    Ok(())
}

/// The reproduction: call 1 keeps its own B leg as an identifier match.
#[test]
fn a_sequential_sipp_call_keeps_its_own_b_leg() -> Result<(), TestError> {
    let (_dir, pcap) = capture("sipp-sequential.pcap", sipp_sequential())?;
    let answer = correlate(&pcap, "1-th-call@example.com")?;
    assert_eq!(
        origin_legs(&answer),
        vec!["1-th-call-b@example.com"],
        "{answer}"
    );
    Ok(())
}

/// The reproduction: calls 2 and 3 are not listed as identifier matches of
/// call 1, by any strategy.
#[test]
fn sequential_sipp_calls_are_not_identifier_matches_of_each_other() -> Result<(), TestError> {
    let (_dir, pcap) = capture("sipp-sequential.pcap", sipp_sequential())?;
    let answer = correlate(&pcap, "1-th-call@example.com")?;
    let identified: Vec<String> = legs(&answer)
        .into_iter()
        .filter(|(_, _, identifier, _)| *identifier)
        .map(|(id, _, _, _)| id)
        .collect();
    assert_eq!(identified, vec!["1-th-call-b@example.com"], "{answer}");
    Ok(())
}

/// A load test: ten concurrent calls with one origin. No leg is an
/// `sdp_origin` match.
#[test]
fn concurrent_calls_sharing_one_origin_have_no_origin_match() -> Result<(), TestError> {
    let calls: Vec<Vec<(Vec<u8>, u64)>> = (0..10_u64)
        .flat_map(|n| {
            let start = n * 100_000;
            [
                leg(
                    &format!("{n}-load@example.com"),
                    UAC,
                    SBC,
                    SIPP_ORIGIN,
                    start,
                    start + 10_000_000,
                ),
                leg(
                    &format!("{n}-load-b@example.com"),
                    SBC,
                    UAS,
                    SIPP_ORIGIN,
                    start + 1_000,
                    start + 9_999_000,
                ),
            ]
        })
        .collect();
    let (_dir, pcap) = capture("load.pcap", calls)?;
    for id in ["0-load@example.com", "5-load-b@example.com"] {
        let answer = correlate(&pcap, id)?;
        assert!(origin_legs(&answer).is_empty(), "{id}: {answer}");
    }
    Ok(())
}

/// `tests/pcap-samples/sip-rtp-g711.pcap` holds two SIPp calls to one
/// FreeSWITCH, one after the other, both with the offer origin `- 42 42 IN
/// IP4 10.0.2.20`. They were listed as one call's two legs; they are not.
#[test]
fn two_consecutive_sipp_calls_in_a_shipped_sample_are_not_tied() -> Result<(), TestError> {
    let answer = correlate("tests/pcap-samples/sip-rtp-g711.pcap", "1-1966@10.0.2.20")?;
    assert_eq!(answer["total_matched"], 0, "{answer}");
    Ok(())
}

/// `tests/fixtures/refer/refer-transfer.pcap` holds two SIPp calls through
/// OpenSIPS, two seconds apart, that reuse the offer and the answer origins.
#[test]
fn two_transfer_calls_in_a_fixture_are_not_tied_by_origin() -> Result<(), TestError> {
    let answer = correlate(
        "tests/fixtures/refer/refer-transfer.pcap",
        "refer-done-1@example.com",
    )?;
    assert!(origin_legs(&answer).is_empty(), "{answer}");
    Ok(())
}

/// An IPv6 origin (RFC 3849) passed through matches.
#[test]
fn an_ipv6_origin_passed_through_matches() -> Result<(), TestError> {
    let (_dir, pcap) = capture(
        "passthrough-ipv6.pcap",
        passthrough("alice 2890844526 2890842807 IN IP6 2001:db8::1"),
    )?;
    let answer = correlate(&pcap, "b@example.com")?;
    assert_eq!(origin_legs(&answer), vec!["a@example.com"], "{answer}");
    Ok(())
}

/// A second leg that starts one microsecond after the first one ended, on
/// another hop, is not tied by the origin.
#[test]
fn a_leg_starting_after_the_other_ended_is_not_tied() -> Result<(), TestError> {
    let (_dir, pcap) = capture(
        "boundary.pcap",
        vec![
            leg("a@example.com", UAC, SBC, ORIGIN, 0, 500_000),
            leg("b@example.com", SBC, UAS, ORIGIN, 500_001, 900_000),
        ],
    )?;
    let answer = correlate(&pcap, "a@example.com")?;
    assert!(origin_legs(&answer).is_empty(), "{answer}");
    Ok(())
}
