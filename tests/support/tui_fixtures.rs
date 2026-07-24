// SPDX-License-Identifier: MIT OR Apache-2.0

//! Shared SIP fixture builders for the TUI tests.
//!
//! Both `tui_state_test.rs` and `tui_snapshot_test.rs` build `App`s from
//! synthetic SIP messages. The low-level constructors (endpoint addresses,
//! the base timestamp, raw-wire assembly, and the minimal INVITE / response
//! builders) were byte-for-byte identical in the two files; they live here so
//! a fixture change can't drift between the state-machine and snapshot suites.
//!
//! Included (not compiled as its own test binary) with
//! `#[path = "support/tui_fixtures.rs"] mod fixtures;` from inside each file's
//! `#[cfg(feature = "tui")]` module.
//!
//! Naming: the endpoints are `10.0.0.x` (ordinary LAN addresses), so they are
//! named `endpoint_a` / `endpoint_b` — the earlier `localhost_*` names were a
//! misnomer (these were never loopback addresses).
#![allow(dead_code)]

use std::net::{IpAddr, Ipv4Addr};

use chrono::{DateTime, Utc};

use sipnab::capture::parse::TransportProto;
use sipnab::sip::SipMessage;
use sipnab::sip::parser::parse_sip;

/// A-side test endpoint address used as the source of requests.
///
/// # Returns
/// `10.0.0.1` — an ordinary LAN address, not loopback.
pub fn endpoint_a() -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
}

/// B-side test endpoint address used as the destination of requests.
///
/// # Returns
/// `10.0.0.2` — an ordinary LAN address, not loopback.
pub fn endpoint_b() -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))
}

/// Fixed reference timestamp all fixture messages are offset from.
///
/// # Returns
/// 2024-06-15 12:00:00 UTC, so tests are independent of wall-clock time.
pub fn base_ts() -> DateTime<Utc> {
    chrono::TimeZone::with_ymd_and_hms(&Utc, 2024, 6, 15, 12, 0, 0).unwrap()
}

/// Assemble raw SIP wire bytes from a first line and header lines.
///
/// # Arguments
/// * `first_line` - Request or status line, without CRLF.
/// * `headers` - Header lines, each without CRLF.
///
/// # Returns
/// CRLF-terminated bytes ending in the blank header/body separator (no body).
pub fn build_sip(first_line: &str, headers: &[&str]) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(first_line.as_bytes());
    msg.extend_from_slice(b"\r\n");
    for h in headers {
        msg.extend_from_slice(h.as_bytes());
        msg.extend_from_slice(b"\r\n");
    }
    msg.extend_from_slice(b"\r\n");
    msg
}

/// Parse a minimal INVITE (A-side to B-side, UDP 5060/5060).
///
/// # Arguments
/// * `call_id` - Call-ID header value.
/// * `from` / `to` - Users placed in the From/To display names and URIs.
/// * `ts` - Capture timestamp.
///
/// # Returns
/// The parsed `SipMessage`; panics if parsing fails.
pub fn make_invite(call_id: &str, from: &str, to: &str, ts: DateTime<Utc>) -> SipMessage {
    let raw = build_sip(
        &format!("INVITE sip:{to}@example.com SIP/2.0"),
        &[
            &format!("From: \"{from}\" <sip:{from}@example.com>;tag=t1"),
            &format!("To: \"{to}\" <sip:{to}@example.com>"),
            &format!("Call-ID: {call_id}"),
            "CSeq: 1 INVITE",
            "Content-Length: 0",
        ],
    );
    parse_sip(
        &raw,
        ts,
        endpoint_a(),
        endpoint_b(),
        5060,
        5060,
        TransportProto::Udp,
    )
    .expect("parse INVITE")
}

/// Parse a SIP response (B-side to A-side) for Alice/Bob's dialog.
///
/// # Arguments
/// * `call_id` - Call-ID header value.
/// * `status` / `reason` - Status line, e.g. 200 "OK".
/// * `cseq_method` - Method echoed in the CSeq header.
/// * `ts` - Capture timestamp.
///
/// # Returns
/// The parsed `SipMessage`; panics if parsing fails.
pub fn make_response(
    call_id: &str,
    status: u16,
    reason: &str,
    cseq_method: &str,
    ts: DateTime<Utc>,
) -> SipMessage {
    let raw = build_sip(
        &format!("SIP/2.0 {status} {reason}"),
        &[
            "From: \"Alice\" <sip:1001@example.com>;tag=t1",
            "To: \"Bob\" <sip:1002@example.com>;tag=t2",
            &format!("Call-ID: {call_id}"),
            &format!("CSeq: 1 {cseq_method}"),
            "Content-Length: 0",
        ],
    );
    parse_sip(
        &raw,
        ts,
        endpoint_b(),
        endpoint_a(),
        5060,
        5060,
        TransportProto::Udp,
    )
    .expect("parse response")
}
