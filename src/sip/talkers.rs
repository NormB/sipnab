// SPDX-License-Identifier: MIT OR Apache-2.0

//! Ranking the busiest participants — "talkers" — by ip, ua, or the dialed
//! number's leading digits.
//!
//! Shared by the MCP `top_talkers` tool and the REST `/v1/talkers` route so the
//! two surfaces rank one store the same way. A dialog counts for every talker
//! that took part in it, so ip and ua shares sum above 100%: a ranking of
//! participants is a different question from one bucket per dialog.
//!
//! Only the `ua` key is sender-authored text. This module returns every key
//! raw; the MCP surface fences the `ua` ones before a value reaches a model,
//! the same split [`dialog_group_value_raw`](crate::sip::dialog::dialog_group_value_raw)
//! makes. [`TalkerDimension::fences_key`] tells a surface which those are.

use crate::sip::SipMessage;
use crate::sip::dialog::SipDialog;
use std::collections::BTreeMap;

/// Digits of the dialed number one `prefix` bucket covers when none is asked
/// for.
///
/// Four, where a North American plan's NPA plus the first NXX digit separates
/// one route from another, and short enough that an international number still
/// groups by country and carrier rather than one row per destination.
pub const DEFAULT_PREFIX_DIGITS: usize = 4;

/// Bucket key when a dialog has no To user at all.
const NO_DESTINATION: &str = "(none)";

/// Bucket key when the To user carries no leading digits — a name, not a
/// number, so it has no dialing prefix.
const NON_NUMERIC_DESTINATION: &str = "(non-numeric)";

/// What a ranking ranks by.
///
/// An enum rather than a raw string threaded through the scan: the string is
/// validated once, at the edge, and every decision below is then a match the
/// compiler checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TalkerDimension {
    /// Addresses that sent messages.
    Ip,
    /// `User-Agent` and `Server` banners.
    Ua,
    /// Leading digits of the dialed number, this many of them.
    Prefix(usize),
}

/// What one talker did, accumulated across the dialogs it took part in.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TalkerAccumulator {
    /// Dialogs the talker appeared in.
    pub dialogs: usize,
    /// Messages attributed to the talker.
    pub messages: usize,
    /// Of `dialogs`, the INVITE ones.
    pub invites: usize,
    /// Of `invites`, the ones that reached a 2xx.
    pub answered: usize,
    /// Of `invites`, the ones that ended 4xx, 5xx or 6xx.
    pub failed: usize,
}

impl TalkerDimension {
    /// Parse `by` and an optional prefix width into a dimension.
    ///
    /// # Errors
    ///
    /// A message (each surface renders it in its own error type) for an unknown
    /// `by`, or a `prefix` asked for with zero digits — a zero-width prefix puts
    /// every destination in one bucket, a ranking of one row that says nothing.
    pub fn parse(by: &str, prefix_digits: Option<u32>) -> Result<Self, String> {
        match by.trim() {
            "ip" => Ok(Self::Ip),
            "ua" => Ok(Self::Ua),
            "prefix" => match prefix_digits {
                Some(0) => Err("prefix_digits must be greater than zero: a \
                                zero-digit prefix is the same bucket for every \
                                destination, so the ranking would have exactly \
                                one row"
                    .to_string()),
                Some(n) => Ok(Self::Prefix(n as usize)),
                None => Ok(Self::Prefix(DEFAULT_PREFIX_DIGITS)),
            },
            other => Err(format!(
                "cannot rank by '{other}'; one of: ip, ua, prefix. One dimension \
                 only — a ranking of pairs answers a different question from a \
                 ranking of either half."
            )),
        }
    }

    /// The dimension's name, for the response.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Ip => "ip",
            Self::Ua => "ua",
            Self::Prefix(_) => "prefix",
        }
    }

    /// Whether a key of this dimension is sender-authored text a surface must
    /// fence. Only `ua` is: an address is sipnab's own read of the headers, and
    /// a prefix is digits this code extracted or a literal it chose.
    #[must_use]
    pub fn fences_key(self) -> bool {
        matches!(self, Self::Ua)
    }

    /// Credit one dialog to every talker that took part in it.
    ///
    /// Adds one dialog to each distinct key the dialog carries, plus the
    /// messages attributed to that key. A key appears at most once per dialog,
    /// so an endpoint that sent forty messages in one call counts as one dialog
    /// and forty messages rather than forty dialogs.
    pub fn credit(self, d: &SipDialog, tally: &mut BTreeMap<String, TalkerAccumulator>) {
        // Key to the messages it accounts for, built per dialog so the
        // de-duplication is structural rather than a second pass.
        let mut per_key: BTreeMap<String, usize> = BTreeMap::new();
        match self {
            // The SENDER. Counting receivers too would rank a proxy top of every
            // capture it appears in for work it did not originate.
            Self::Ip => {
                for m in &d.messages {
                    *per_key.entry(m.src_addr.to_string()).or_insert(0) += 1;
                }
            }
            // `banner_of` reads `User-Agent` off requests and `Server` off
            // responses, so each banner names the party that wrote it.
            Self::Ua => {
                for m in &d.messages {
                    if let Some((_, value)) = banner_of(m) {
                        *per_key.entry(value).or_insert(0) += 1;
                    }
                }
            }
            // One bucket per dialog: a dialog has one dialed number.
            Self::Prefix(digits) => {
                per_key.insert(prefix_key(d.to_user.as_deref(), digits), d.messages.len());
            }
        }

        let invite = d.method == crate::sip::method::SipMethod::Invite;
        let final_code = d.final_status_code();
        let answered = invite && final_code.is_some_and(|c| (200..300).contains(&c));
        let failed = invite && final_code.is_some_and(|c| c >= 400);

        for (key, messages) in per_key {
            let acc = tally.entry(key).or_default();
            acc.dialogs += 1;
            acc.messages += messages;
            if invite {
                acc.invites += 1;
                if answered {
                    acc.answered += 1;
                }
                if failed {
                    acc.failed += 1;
                }
            }
        }
    }
}

/// The prefix bucket a dialed number falls into.
///
/// Leading digits only, after an optional `+`: an E.164 number is written both
/// ways on one wire, and bucketing `+15551234` apart from `15551234` would
/// split one destination in two. A destination with no digits gets a named
/// literal rather than being dropped — "how much goes to a name" is a real
/// question a silently-omitting bucket set would not answer.
fn prefix_key(to_user: Option<&str>, digits: usize) -> String {
    let Some(user) = to_user else {
        return NO_DESTINATION.to_string();
    };
    let leading: String = user
        .strip_prefix('+')
        .unwrap_or(user)
        .chars()
        .take_while(char::is_ascii_digit)
        .take(digits)
        .collect();
    if leading.is_empty() {
        return NON_NUMERIC_DESTINATION.to_string();
    }
    leading
}

/// The banner one message carries about ITS OWN sender, if any.
///
/// `User-Agent` on a request and `Server` on a response, per RFC 3261 §20.41
/// and §20.35. A request's `Server` header and a response's `User-Agent`
/// describe the other direction, so reading them here would file the far end's
/// software under this endpoint.
///
/// `pub` because `describe_endpoint` reads the same banner; one reader, so the
/// two tools cannot come to disagree about whose software a header names.
pub fn banner_of(m: &SipMessage) -> Option<(String, String)> {
    if m.is_request {
        m.header("User-Agent")
            .map(|v| ("User-Agent".to_string(), v.to_string()))
    } else {
        m.header("Server")
            .map(|v| ("Server".to_string(), v.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::TransportProto;
    use crate::sip::dialog::update_state;
    use crate::sip::parser::parse_sip;
    use crate::test_utils::build_sip_message as build_sip;
    use chrono::{TimeZone, Utc};
    use std::net::{IpAddr, Ipv4Addr};

    fn ts() -> chrono::DateTime<Utc> {
        Utc.with_ymd_and_hms(2024, 6, 15, 12, 0, 0).unwrap()
    }

    /// An INVITE dialog from `src` to `to_user`, ending at `final_code`, with a
    /// `User-Agent` banner. Built through the ingest path so the accessors agree.
    fn call(call_id: &str, src: IpAddr, to_user: &str, ua: &str, final_code: u16) -> SipDialog {
        let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9));
        let inv = build_sip(
            &format!("INVITE sip:{to_user}@example.com SIP/2.0"),
            &[
                "From: <sip:alice@example.com>;tag=t1",
                &format!("To: <sip:{to_user}@example.com>"),
                &format!("Call-ID: {call_id}"),
                "CSeq: 1 INVITE",
                &format!("User-Agent: {ua}"),
                "Content-Length: 0",
            ],
            b"",
        );
        let invite =
            parse_sip(&inv, ts(), src, dst, 5060, 5060, TransportProto::Udp).expect("parse");
        let mut d = SipDialog::new(&invite).expect("dialog");
        let rsp = build_sip(
            &format!("SIP/2.0 {final_code} X"),
            &[
                "From: <sip:alice@example.com>;tag=t1",
                &format!("To: <sip:{to_user}@example.com>;tag=t2"),
                &format!("Call-ID: {call_id}"),
                "CSeq: 1 INVITE",
                "Content-Length: 0",
            ],
            b"",
        );
        let resp = parse_sip(&rsp, ts(), dst, src, 5060, 5060, TransportProto::Udp).expect("parse");
        update_state(&mut d, &resp);
        d.messages.push(resp);
        d
    }

    /// By ip, the busiest SENDER ranks first and a dialog counts once for it,
    /// with INVITE outcomes credited: an answered call and a failed one from one
    /// address give it 2 dialogs, 2 invites, 1 answered, 1 failed.
    #[test]
    fn credit_by_ip_counts_the_sender_and_its_outcomes() {
        let a = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let mut tally = BTreeMap::new();
        TalkerDimension::Ip.credit(&call("c1", a, "15551234000", "UA/1", 200), &mut tally);
        TalkerDimension::Ip.credit(&call("c2", a, "15551234001", "UA/1", 486), &mut tally);
        let acc = tally.get("192.0.2.1").expect("the sender is a talker");
        assert_eq!(acc.dialogs, 2);
        assert_eq!(acc.invites, 2);
        assert_eq!(acc.answered, 1);
        assert_eq!(acc.failed, 1);
        // The response comes back FROM 10.0.0.9, so it is a talker too, but the
        // ranking of senders keeps them apart.
        assert!(tally.contains_key("10.0.0.9"), "the responder also sent");

        // A message's SENDER is the talker, never its receiver. The two calls
        // above are symmetric — each address is both a src and a dst — so they
        // cannot tell the rule from its opposite. An INVITE-only dialog to a
        // destination that never replies can: only the sender appears, and
        // crediting the destination instead would put it here and drop the
        // sender.
        let sender = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9));
        let never_sends = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5));
        let raw = build_sip(
            "INVITE sip:x@example.com SIP/2.0",
            &[
                "From: <sip:z@example.com>;tag=t9",
                "To: <sip:x@example.com>",
                "Call-ID: probe@h",
                "CSeq: 1 INVITE",
                "Content-Length: 0",
            ],
            b"",
        );
        let inv = parse_sip(
            &raw,
            ts(),
            sender,
            never_sends,
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("parse");
        TalkerDimension::Ip.credit(&SipDialog::new(&inv).expect("dialog"), &mut tally);
        assert!(
            tally.contains_key("192.0.2.9"),
            "the INVITE sender is a talker"
        );
        assert!(
            !tally.contains_key("203.0.113.5"),
            "the destination never sent, so crediting it would be wrong"
        );
    }

    /// By ua, the key is the banner the sender wrote, and that dimension is the
    /// only one a surface fences.
    #[test]
    fn credit_by_ua_keys_on_the_banner_and_is_fenced() {
        let a = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let mut tally = BTreeMap::new();
        TalkerDimension::Ua.credit(
            &call("c1", a, "15551234000", "Sipnabophone/9", 200),
            &mut tally,
        );
        assert!(
            tally.contains_key("Sipnabophone/9"),
            "keyed on the UA banner"
        );
        assert!(TalkerDimension::Ua.fences_key(), "ua is sender-authored");
        assert!(!TalkerDimension::Ip.fences_key(), "ip is sipnab's own read");
    }

    /// By prefix, the dialed number buckets on its leading digits, a `+` is
    /// ignored so one destination is not split, and a non-numeric or absent
    /// destination gets a named literal rather than vanishing.
    #[test]
    fn prefix_buckets_on_leading_digits() {
        assert_eq!(prefix_key(Some("15551234000"), 4), "1555");
        assert_eq!(prefix_key(Some("+15551234000"), 4), "1555");
        assert_eq!(prefix_key(Some("support"), 4), NON_NUMERIC_DESTINATION);
        assert_eq!(prefix_key(None, 4), NO_DESTINATION);
    }

    /// The dimension is validated at the edge: an unknown `by` and a zero-width
    /// prefix are refused with a reason, and a bare `prefix` takes the default.
    #[test]
    fn parse_refuses_unknown_and_zero_width_prefix() {
        assert_eq!(TalkerDimension::parse("ip", None), Ok(TalkerDimension::Ip));
        assert_eq!(
            TalkerDimension::parse("prefix", None),
            Ok(TalkerDimension::Prefix(DEFAULT_PREFIX_DIGITS))
        );
        assert_eq!(
            TalkerDimension::parse("prefix", Some(6)),
            Ok(TalkerDimension::Prefix(6))
        );
        assert!(TalkerDimension::parse("prefix", Some(0)).is_err());
        assert!(TalkerDimension::parse("pairs", None).is_err());
    }
}
