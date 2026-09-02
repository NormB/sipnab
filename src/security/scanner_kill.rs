// SPDX-License-Identifier: MIT OR Apache-2.0

//! Scanner kill — SIP response construction for active scanner countermeasures.
//!
//! Builds minimal valid SIP responses to send back to detected scanners.
//! The response copies mandatory headers from the original request (Via, From,
//! To, Call-ID, CSeq) per RFC 3261 SS8.2.6, keeping the scanner's state
//! machine satisfied while wasting its resources.

use std::net::IpAddr;

use crate::capture::parse::InputOrigin;
use crate::sip::SipMessage;

/// A targeted-kill directive (`--kill-target`): an IP address
/// and an optional inclusive source-port range. A SIP request whose source
/// matches is killed regardless of UA/behavioral scanner detection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KillTarget {
    /// The IP address that must match the SIP request source.
    ip: IpAddr,
    /// Inclusive `(lo, hi)` source-port range; `None` matches any port.
    ports: Option<(u16, u16)>,
}

impl KillTarget {
    /// Parse a `-K` / `--kill-target` spec into a `KillTarget`.
    ///
    /// Accepted forms:
    /// - `ADDR` — bare IPv4/IPv6, matches any source port (`10.0.0.1`, `::1`).
    /// - `ADDR:PORT` — a single port (`10.0.0.1:5060`).
    /// - `ADDR:LO-HI` — an inclusive port range (`10.0.0.1:5060-5090`).
    ///
    /// IPv6 with a port MUST be bracketed (`[::1]:5060`) so the address colons
    /// are unambiguous; a bare IPv6 (no port) needs no brackets.
    ///
    /// # Errors
    ///
    /// Returns a human-readable message when the address is invalid, the port
    /// spec is malformed, or a range is inverted (`lo > hi`).
    pub fn parse(spec: &str) -> Result<Self, String> {
        if spec.is_empty() {
            return Err("empty kill-target".to_string());
        }

        // Bracketed IPv6: `[addr]` or `[addr]:portspec`.
        if let Some(rest) = spec.strip_prefix('[') {
            let end = rest
                .find(']')
                .ok_or_else(|| format!("unclosed '[' in '{spec}'"))?;
            let ip: IpAddr = rest[..end]
                .parse()
                .map_err(|_| format!("invalid IPv6 address in '{spec}'"))?;
            let after = &rest[end + 1..];
            let ports = if after.is_empty() {
                None
            } else {
                let port_spec = after
                    .strip_prefix(':')
                    .ok_or_else(|| format!("expected ':port' after ']' in '{spec}'"))?;
                Some(parse_port_range(port_spec)?)
            };
            return Ok(Self { ip, ports });
        }

        // A bare address (IPv4 or unbracketed IPv6) with no port spec.
        if let Ok(ip) = spec.parse::<IpAddr>() {
            return Ok(Self { ip, ports: None });
        }

        // Otherwise it must be `ADDR:portspec`. Split on the FIRST colon; a
        // valid IPv4 has none, so anything left containing a colon (an
        // unbracketed IPv6 + port) fails the address parse below — as intended.
        let (ip_str, port_spec) = spec
            .split_once(':')
            .ok_or_else(|| format!("invalid kill-target '{spec}'"))?;
        let ip: IpAddr = ip_str
            .parse()
            .map_err(|_| format!("invalid address '{ip_str}' in '{spec}'"))?;
        Ok(Self {
            ip,
            ports: Some(parse_port_range(port_spec)?),
        })
    }

    /// True if a SIP request from `src_ip:src_port` matches this target.
    pub fn matches(&self, src_ip: IpAddr, src_port: u16) -> bool {
        self.ip == src_ip
            && self
                .ports
                .is_none_or(|(lo, hi)| (lo..=hi).contains(&src_port))
    }
}

/// Parse a `LO-HI` inclusive range or a single `PORT` into `(lo, hi)`.
fn parse_port_range(spec: &str) -> Result<(u16, u16), String> {
    if let Some((lo_str, hi_str)) = spec.split_once('-') {
        let lo: u16 = lo_str
            .parse()
            .map_err(|_| format!("invalid port '{lo_str}'"))?;
        let hi: u16 = hi_str
            .parse()
            .map_err(|_| format!("invalid port '{hi_str}'"))?;
        if lo > hi {
            return Err(format!("inverted port range {lo}-{hi}"));
        }
        Ok((lo, hi))
    } else {
        let p: u16 = spec.parse().map_err(|_| format!("invalid port '{spec}'"))?;
        Ok((p, p))
    }
}

/// Standard SIP reason phrases for common response codes.
fn reason_phrase(code: u16) -> &'static str {
    match code {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        480 => "Temporarily Unavailable",
        486 => "Busy Here",
        487 => "Request Terminated",
        488 => "Not Acceptable Here",
        500 => "Server Internal Error",
        503 => "Service Unavailable",
        603 => "Decline",
        _ => "Unknown",
    }
}

/// Whether a scanner-kill active response may be sent for a packet, given
/// where its addressing came from and whether the operator opted in with
/// `--hep-allow-kill`.
///
/// HEP-origin packets are ineligible by default (SN-01): a HEP sender
/// asserts the inner src/dst addresses, so absent receiver-side
/// authentication an attacker could steer the kill response at a chosen
/// victim (SSRF-style). Live/pcap traffic, whose addressing comes from an
/// observed IP header, is always eligible.
pub fn kill_response_eligible(origin: InputOrigin, hep_allow_kill: bool) -> bool {
    match origin {
        // sipnab read the addressing off the wire itself.
        InputOrigin::Wire => true,
        // A remote sender asserted it; trust it only on explicit opt-in.
        InputOrigin::Hep => hep_allow_kill,
        // There is no addressing. Bytes lifted out of a process carry no
        // socket, so any response would be aimed at a guess — and NO opt-in is
        // offered, because an opt-in here would be an invitation to transmit at
        // one. `--hep-allow-kill` deliberately does not reach this arm.
        InputOrigin::Uprobe => false,
    }
}

/// Build a minimal SIP response to send back to a scanner.
///
/// Copies mandatory dialog-identifying headers (Via, From, To, Call-ID, CSeq)
/// from the original request per RFC 3261 SS8.2.6. A `tag` parameter is
/// appended to the To header if one is not already present.
///
/// Returns `None` if the message is not a request or lacks required headers.
///
/// # Arguments
///
/// * `original_msg` — The SIP request that triggered the scanner alert.
/// * `response_code` — The SIP response code (e.g., 200, 403, 404).
pub fn build_scanner_response(original_msg: &SipMessage, response_code: u16) -> Option<Vec<u8>> {
    // Only build responses for requests
    if !original_msg.is_request {
        return None;
    }

    let reason = reason_phrase(response_code);

    // Extract required headers from the original request
    let via_headers = original_msg.via_headers();
    if via_headers.is_empty() {
        return None;
    }
    let from = original_msg.from_header()?;
    let to_raw = original_msg.to_header()?;
    let call_id = original_msg.call_id()?;
    let cseq_raw = original_msg.header("CSeq")?;

    // Build the To header with a tag if not already present
    let to_value = if to_raw.contains("tag=") {
        to_raw.to_string()
    } else {
        // Generate a deterministic tag from Call-ID to avoid randomness
        let tag_hash = simple_hash(call_id.as_bytes());
        format!("{to_raw};tag=sn-{tag_hash:08x}")
    };

    let mut response = Vec::with_capacity(512);

    // Status line
    response.extend_from_slice(format!("SIP/2.0 {response_code} {reason}\r\n").as_bytes());

    // Via headers (all of them, in order)
    for via in &via_headers {
        response.extend_from_slice(format!("Via: {via}\r\n").as_bytes());
    }

    // From (copied verbatim)
    response.extend_from_slice(format!("From: {from}\r\n").as_bytes());

    // To (with tag added)
    response.extend_from_slice(format!("To: {to_value}\r\n").as_bytes());

    // Call-ID
    response.extend_from_slice(format!("Call-ID: {call_id}\r\n").as_bytes());

    // CSeq
    response.extend_from_slice(format!("CSeq: {cseq_raw}\r\n").as_bytes());

    // Content-Length: 0
    response.extend_from_slice(b"Content-Length: 0\r\n");

    // End of headers
    response.extend_from_slice(b"\r\n");

    Some(response)
}

/// Simple non-cryptographic hash for generating deterministic To-tags.
fn simple_hash(data: &[u8]) -> u32 {
    let mut h: u32 = 0x811c_9dc5;
    for &b in data {
        h ^= u32::from(b);
        h = h.wrapping_mul(0x0100_0193);
    }
    h
}

// ── Tests ────────────────────────────────────────────────────────────

/// Unit tests for scanner-kill response building and kill-target parsing.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::TransportProto;
    use crate::sip::parser::parse_sip;
    use chrono::{DateTime, Utc};
    use std::net::{IpAddr, Ipv4Addr};

    /// The source IP used to simulate a scanner.
    fn scanner_ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 99))
    }

    /// HEP-origin traffic is kill-ineligible by default and eligible only on
    /// opt-in; live/pcap traffic is always eligible.
    #[test]
    fn kill_eligibility_blocks_unauthed_hep_by_default() {
        // Live/pcap traffic is always eligible.
        assert!(kill_response_eligible(InputOrigin::Wire, false));
        assert!(kill_response_eligible(InputOrigin::Wire, true));
        // HEP-origin traffic is blocked unless the operator opts in.
        assert!(
            !kill_response_eligible(InputOrigin::Hep, false),
            "HEP kill blocked by default"
        );
        assert!(
            kill_response_eligible(InputOrigin::Hep, true),
            "opt-in re-enables HEP kill"
        );
    }

    /// The third case, and the strictest. A uprobe read carries NO addressing:
    /// sipnab never saw a socket, so there is nowhere honest to send a
    /// response. Unlike HEP this has no opt-in, and `--hep-allow-kill` must
    /// not reach it — an opt-in here would be an invitation to transmit at a
    /// guess.
    #[test]
    fn uprobe_origin_is_never_kill_eligible_and_has_no_opt_in() {
        assert!(
            !kill_response_eligible(InputOrigin::Uprobe, false),
            "uprobe reads carry no address to respond to"
        );
        assert!(
            !kill_response_eligible(InputOrigin::Uprobe, true),
            "--hep-allow-kill must NOT re-enable transmission for uprobe input; \
             it is an opt-in about HEP, and uprobe input has no address at all"
        );
    }

    /// The local address used as the packet destination.
    fn local_ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))
    }

    /// A fixed capture timestamp for the parsed messages.
    fn ts() -> DateTime<Utc> {
        chrono::TimeZone::with_ymd_and_hms(&Utc, 2024, 6, 15, 12, 0, 0).unwrap()
    }

    use crate::test_utils::build_sip_message;

    /// Build raw SIP request bytes with an empty body.
    fn build_sip_bytes(first_line: &str, headers: &[&str]) -> Vec<u8> {
        build_sip_message(first_line, headers, b"")
    }

    /// Build an INVITE request with a single Via and no To-tag.
    fn make_invite() -> SipMessage {
        let raw = build_sip_bytes(
            "INVITE sip:target@example.com SIP/2.0",
            &[
                "Via: SIP/2.0/UDP 10.0.0.99:5060;branch=z9hG4bK-test",
                "From: <sip:scanner@example.com>;tag=from1",
                "To: <sip:target@example.com>",
                "Call-ID: invite-kill-test@example.com",
                "CSeq: 1 INVITE",
                "User-Agent: friendly-scanner",
                "Content-Length: 0",
            ],
        );
        parse_sip(
            &raw,
            ts(),
            scanner_ip(),
            local_ip(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("parse")
    }

    /// Build an OPTIONS request with two Via headers and an existing To-tag.
    fn make_options() -> SipMessage {
        let raw = build_sip_bytes(
            "OPTIONS sip:target@example.com SIP/2.0",
            &[
                "Via: SIP/2.0/UDP 10.0.0.99:5060;branch=z9hG4bK-opt1",
                "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-proxy",
                "From: <sip:scanner@example.com>;tag=from2",
                "To: <sip:target@example.com>;tag=existing",
                "Call-ID: options-kill-test@example.com",
                "CSeq: 42 OPTIONS",
                "Content-Length: 0",
            ],
        );
        parse_sip(
            &raw,
            ts(),
            scanner_ip(),
            local_ip(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("parse")
    }

    /// A 200 OK response copies the request's Via/From/Call-ID/CSeq and adds a
    /// To-tag.
    #[test]
    fn build_200_ok_for_invite() {
        let msg = make_invite();
        let resp = build_scanner_response(&msg, 200).expect("should build response");
        let text = String::from_utf8(resp).expect("valid utf8");

        assert!(text.starts_with("SIP/2.0 200 OK\r\n"));
        assert!(text.contains("Via: SIP/2.0/UDP 10.0.0.99:5060;branch=z9hG4bK-test\r\n"));
        assert!(text.contains("From: <sip:scanner@example.com>;tag=from1\r\n"));
        assert!(text.contains("Call-ID: invite-kill-test@example.com\r\n"));
        assert!(text.contains("CSeq: 1 INVITE\r\n"));
        assert!(text.contains("Content-Length: 0\r\n"));
        // To should have a tag added
        assert!(text.contains("To: <sip:target@example.com>;tag=sn-"));
        assert!(text.ends_with("\r\n\r\n"));
    }

    /// A 404 response uses the "Not Found" reason phrase.
    #[test]
    fn build_404_response() {
        let msg = make_invite();
        let resp = build_scanner_response(&msg, 404).expect("should build response");
        let text = String::from_utf8(resp).expect("valid utf8");

        assert!(text.starts_with("SIP/2.0 404 Not Found\r\n"));
    }

    /// A 403 response uses the "Forbidden" reason phrase.
    #[test]
    fn build_403_response() {
        let msg = make_invite();
        let resp = build_scanner_response(&msg, 403).expect("should build response");
        let text = String::from_utf8(resp).expect("valid utf8");

        assert!(text.starts_with("SIP/2.0 403 Forbidden\r\n"));
    }

    /// An existing To-tag is preserved and no synthetic tag is added.
    #[test]
    fn preserves_existing_to_tag() {
        let msg = make_options();
        let resp = build_scanner_response(&msg, 200).expect("should build response");
        let text = String::from_utf8(resp).expect("valid utf8");

        // Existing tag should be preserved, not doubled
        assert!(text.contains("To: <sip:target@example.com>;tag=existing\r\n"));
        assert!(!text.contains("tag=sn-"));
    }

    /// All Via headers from the request are copied in order.
    #[test]
    fn preserves_multiple_via_headers() {
        let msg = make_options();
        let resp = build_scanner_response(&msg, 200).expect("should build response");
        let text = String::from_utf8(resp).expect("valid utf8");

        assert!(text.contains("Via: SIP/2.0/UDP 10.0.0.99:5060;branch=z9hG4bK-opt1\r\n"));
        assert!(text.contains("Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-proxy\r\n"));
    }

    /// The response echoes the request's CSeq verbatim.
    #[test]
    fn response_contains_correct_cseq() {
        let msg = make_options();
        let resp = build_scanner_response(&msg, 200).expect("should build response");
        let text = String::from_utf8(resp).expect("valid utf8");

        assert!(text.contains("CSeq: 42 OPTIONS\r\n"));
    }

    /// Building a response for a SIP response message returns `None`.
    #[test]
    fn returns_none_for_response_message() {
        let raw = build_sip_bytes(
            "SIP/2.0 200 OK",
            &[
                "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-test",
                "From: <sip:alice@example.com>;tag=t1",
                "To: <sip:bob@example.com>;tag=t2",
                "Call-ID: resp-test@example.com",
                "CSeq: 1 INVITE",
                "Content-Length: 0",
            ],
        );
        let msg = parse_sip(
            &raw,
            ts(),
            scanner_ip(),
            local_ip(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("parse");
        assert!(build_scanner_response(&msg, 200).is_none());
    }

    /// An unrecognized response code uses the "Unknown" reason phrase.
    #[test]
    fn unknown_response_code_uses_unknown_reason() {
        let msg = make_invite();
        let resp = build_scanner_response(&msg, 699).expect("should build response");
        let text = String::from_utf8(resp).expect("valid utf8");

        assert!(text.starts_with("SIP/2.0 699 Unknown\r\n"));
    }

    // ── KillTarget (targeted kill) ───────────────────────────────────

    /// Construct an IPv4 `IpAddr` from four octets.
    fn ip4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    /// A bare IPv4 target matches that address on any source port.
    #[test]
    fn parse_bare_ipv4_matches_any_port() {
        let t = KillTarget::parse("10.0.0.1").expect("valid");
        assert!(t.matches(ip4(10, 0, 0, 1), 5060));
        assert!(t.matches(ip4(10, 0, 0, 1), 1));
        assert!(t.matches(ip4(10, 0, 0, 1), 65535));
        assert!(!t.matches(ip4(10, 0, 0, 2), 5060));
    }

    /// An `ADDR:PORT` target matches only that single source port.
    #[test]
    fn parse_ipv4_single_port() {
        let t = KillTarget::parse("10.0.0.1:5060").expect("valid");
        assert!(t.matches(ip4(10, 0, 0, 1), 5060));
        assert!(!t.matches(ip4(10, 0, 0, 1), 5061));
    }

    /// An `ADDR:LO-HI` target matches ports inclusive of both boundaries.
    #[test]
    fn parse_ipv4_port_range_inclusive() {
        let t = KillTarget::parse("10.0.0.1:5060-5090").expect("valid");
        assert!(t.matches(ip4(10, 0, 0, 1), 5060)); // lo boundary
        assert!(t.matches(ip4(10, 0, 0, 1), 5075));
        assert!(t.matches(ip4(10, 0, 0, 1), 5090)); // hi boundary
        assert!(!t.matches(ip4(10, 0, 0, 1), 5059));
        assert!(!t.matches(ip4(10, 0, 0, 1), 5091));
        assert!(!t.matches(ip4(10, 0, 0, 2), 5075)); // wrong ip
    }

    /// A bare IPv6 target matches any port; a bracketed IPv6 range honors its
    /// bounds.
    #[test]
    fn parse_bare_ipv6_and_bracketed_with_port() {
        let bare = KillTarget::parse("::1").expect("valid bare v6");
        let v6 = IpAddr::V6(std::net::Ipv6Addr::LOCALHOST);
        assert!(bare.matches(v6, 12345));

        let bracketed = KillTarget::parse("[::1]:5060-5061").expect("valid bracketed v6");
        assert!(bracketed.matches(v6, 5060));
        assert!(bracketed.matches(v6, 5061));
        assert!(!bracketed.matches(v6, 5062));
    }

    /// Malformed kill-target specs are hard parse errors, not permissive
    /// matches.
    #[test]
    fn parse_rejects_invalid_specs() {
        // Each of these must be a hard error, not a silently-permissive target.
        for bad in [
            "",                   // empty
            "not-an-ip",          // garbage
            "999.0.0.1",          // bad octet
            "10.0.0.1:abc",       // non-numeric port
            "10.0.0.1:",          // empty port spec
            "10.0.0.1:5060-",     // empty range hi
            "10.0.0.1:-5090",     // empty range lo
            "10.0.0.1:5090-5060", // lo > hi
            "10.0.0.1:70000",     // port out of u16 range
            "gggg::1:5060",       // not a valid IPv6, and not ADDR:port
            "[::1",               // unclosed bracket
            "[::1]:99999",        // bracketed v6 with out-of-range port
            "10.0.0.1:5060\\",    // trailing backslash junk
        ] {
            assert!(
                KillTarget::parse(bad).is_err(),
                "expected error for {bad:?}"
            );
        }
    }
}
