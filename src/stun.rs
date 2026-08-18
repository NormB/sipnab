// SPDX-License-Identifier: MIT OR Apache-2.0

//! STUN ([RFC 5389](https://www.rfc-editor.org/rfc/rfc5389)) parsing, and the
//! one failure an operator most needs told about: a Binding Request that never
//! came back.
//!
//! # Why a SIP tool parses STUN at all
//!
//! STUN is how an endpoint behind NAT learns the address the outside world sees
//! it as, and that address is what it writes into its SDP. When STUN fails the
//! phone does not stop — it falls back to the only address it knows, which is
//! its private one, and offers that. The call then signals perfectly, answers
//! `200`, and carries audio in one direction, because the far end is sending
//! media to an address that does not exist on the public internet.
//!
//! That chain is invisible if the capture is read as "SIP and everything else".
//! A capture holding nothing but two unanswered Binding Requests is not an
//! empty capture — it is the *cause* of a one-way-audio complaint, and the
//! honest reading of it is "the phone asked who it was and nobody answered",
//! not "no SIP traffic found".
//!
//! # What is parsed, and what is deliberately not
//!
//! Enough to identify a message, pair a response to its request, and name the
//! reflexive address or error the peer returned:
//!
//! * the 20-byte header — type, length, magic cookie and 96-bit transaction ID
//! * `XOR-MAPPED-ADDRESS`, which carries the answer the endpoint asked for
//! * `ERROR-CODE`, so a refusal reads as a refusal rather than as silence
//! * `SOFTWARE`, because it names the stack and is what distinguishes one
//!   vendor's retransmission pattern from another's
//!
//! Not parsed: `MESSAGE-INTEGRITY` and `MESSAGE-INTEGRITY-SHA256`. Those decide
//! whether a message is *authentic*, which needs credentials a passive observer
//! does not have — and reporting anything about them would claim a verification
//! that never happened.
//!
//! `FINGERPRINT` is the opposite case and IS checked, correcting what this
//! comment said when the module landed: it is a CRC-32 over the message with no
//! key involved, so a passive reader can verify it honestly. It is also what
//! separates a real STUN message from a payload that merely happened to carry
//! the cookie bytes.
//!
//! `REALM`, `NONCE` and `USERNAME` are read for what they SAY — that a server
//! asked for credentials, which is a different fault from a path that drops
//! packets — never as evidence that authentication succeeded.
//!
//! sipnab is not an ICE agent. It reports the ICE attributes that explain a
//! media path (who was controlling, which candidate was nominated) and does not
//! compute priorities, form candidate pairs, or decide nominations.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Mutex;

/// The magic cookie every RFC 5389 message carries in bytes 4..8. Also what
/// makes STUN safely detectable inside a stream of arbitrary UDP: the value is
/// fixed, and it is checked before anything else is believed.
pub const MAGIC_COOKIE: u32 = 0x2112_A442;

/// A STUN message class, which is the half of the type field that says whether
/// this is a question or an answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StunClass {
    /// A question. `Binding` requests are what an endpoint sends to learn its
    /// reflexive address.
    Request,
    /// A request that expects no answer, so its absence is not a fault.
    Indication,
    /// The answer, carrying `XOR-MAPPED-ADDRESS`.
    SuccessResponse,
    /// The answer, carrying `ERROR-CODE`.
    ErrorResponse,
}

/// Which side of an ICE exchange drives nomination.
///
/// Reported, not decided: sipnab is an observer. Its value is that a capture
/// where BOTH sides claim `Controlling` is a role conflict — a real
/// misconfiguration whose only other symptom is media that never starts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IceRole {
    /// This agent picks the pair. `ICE-CONTROLLING` (0x802A).
    Controlling,
    /// This agent accepts the other's choice. `ICE-CONTROLLED` (0x8029).
    Controlled,
}

/// One parsed STUN message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StunMessage {
    /// Request / indication / success / error.
    pub class: StunClass,
    /// The method, `0x001` for Binding. Kept as a number rather than an enum
    /// because a capture may legitimately hold TURN methods this module does
    /// not interpret, and reporting "method 3" is more use than discarding it.
    pub method: u16,
    /// The 96-bit transaction ID, which is what pairs an answer to its
    /// question. Compared as bytes; never parsed as a number.
    pub transaction_id: [u8; 12],
    /// The reflexive address the peer reported, when this is a success
    /// response carrying `XOR-MAPPED-ADDRESS`.
    pub mapped_address: Option<SocketAddr>,
    /// The error the peer returned, when this is an error response.
    pub error_code: Option<u16>,
    /// The `SOFTWARE` attribute, when present.
    pub software: Option<String>,
    /// TURN `XOR-RELAYED-ADDRESS`: the address the relay allocated. The TURN
    /// counterpart of `mapped_address` — what the endpoint will advertise.
    pub relayed_address: Option<SocketAddr>,
    /// TURN `XOR-PEER-ADDRESS`: who the permission or send is about.
    pub peer_address: Option<SocketAddr>,
    /// TURN `LIFETIME`, in seconds. A zero lifetime on a Refresh is a
    /// deliberate teardown, not a failure.
    pub lifetime: Option<u32>,
    /// The `REALM` a server challenged with.
    ///
    /// Read for what it SAYS, never as evidence that anyone authenticated: a
    /// realm means the server asked for credentials, which is a different
    /// fault from a path that drops packets and is fixed somewhere else
    /// entirely. Whether the credentials were then correct is a question
    /// `MESSAGE-INTEGRITY` answers, and a passive observer cannot check it.
    pub realm: Option<String>,
    /// Whether a `NONCE` was present. The value itself is not kept — it is a
    /// server-chosen opaque string that says nothing to an observer, and
    /// storing it would only invite someone to treat it as identifying.
    pub nonce_present: bool,
    /// `ALTERNATE-SERVER`: where a `300` redirect points.
    ///
    /// Without it a redirect reads as a dead end, because the error code alone
    /// says the request did not succeed and not that somewhere else would.
    pub alternate_server: Option<SocketAddr>,
    /// Whether the message's `FINGERPRINT` checked out.
    ///
    /// `Some(true)` verified, `Some(false)` present and WRONG, `None` absent.
    /// The three are deliberately distinct: `None` means sipnab did not check,
    /// and reporting that as `false` would accuse a message nobody examined.
    ///
    /// Unlike `MESSAGE-INTEGRITY`, this needs no credentials — it is a CRC-32
    /// over the message — so it is a claim a passive observer can honestly
    /// make, and it is what tells a real STUN message from a payload that
    /// merely happened to carry the cookie bytes.
    pub fingerprint_valid: Option<bool>,
    /// `USE-CANDIDATE`: this check nominates its pair for media.
    ///
    /// The nomination is the finding. Without it, a capture of an ICE exchange
    /// that converged and one that never did look alike.
    pub use_candidate: bool,
    /// `PRIORITY` of the candidate this check is for.
    pub priority: Option<u32>,
    /// Which role the sender claimed, when it claimed one.
    pub ice_role: Option<IceRole>,
    /// TURN `CHANNEL-NUMBER`: which channel carries relayed media.
    pub channel_number: Option<u16>,
    /// TURN `REQUESTED-TRANSPORT`, as an IP protocol number (17 is UDP).
    pub requested_transport: Option<u8>,
    /// Whether [`Self::mapped_address`] came from the XOR form. Tracked so a
    /// legacy `MAPPED-ADDRESS` arriving AFTER the XOR one cannot overwrite it,
    /// whichever order a server sends them in.
    pub mapped_address_is_xor: bool,
}

impl StunMessage {
    /// Whether this message is a Binding Request — the one an unanswered
    /// request report is about.
    pub fn is_binding_request(&self) -> bool {
        self.class == StunClass::Request && self.method == 0x001
    }

    /// Whether this response is an AUTHENTICATION challenge rather than a
    /// refusal or a failure.
    ///
    /// The distinction directs the work: a challenge means the server was
    /// reachable and wants credentials, so nothing in the network path is at
    /// fault. `401` (unauthorized) and `438` (stale nonce) are the two the RFC
    /// defines for this, and a realm is what makes the challenge answerable.
    pub fn is_auth_challenge(&self) -> bool {
        matches!(self.error_code, Some(401) | Some(438)) && self.realm.is_some()
    }

    /// Whether this is a TURN Allocate Request.
    ///
    /// TURN ([RFC 5766](https://www.rfc-editor.org/rfc/rfc5766)) reuses the
    /// STUN header, cookie, transaction ID and attribute layout, so the framing
    /// above parses it without knowing it exists. What does NOT come free is
    /// what the methods MEAN, which is why this is asked separately: an
    /// unanswered `Allocate` says the relay would not give the endpoint an
    /// address, while an unanswered `Binding` says nobody told it its own. Both
    /// end in one-way audio and they are fixed in different places.
    pub fn is_allocate_request(&self) -> bool {
        self.class == StunClass::Request && self.method == METHOD_ALLOCATE
    }

    /// The method's name, for a report a human reads. Unknown methods render
    /// as their number rather than as "unknown", because the number is the
    /// thing to look up.
    pub fn method_name(&self) -> String {
        match self.method {
            0x001 => "Binding".to_string(),
            METHOD_ALLOCATE => "Allocate".to_string(),
            0x004 => "Refresh".to_string(),
            0x006 => "Send".to_string(),
            0x007 => "Data".to_string(),
            0x008 => "CreatePermission".to_string(),
            0x009 => "ChannelBind".to_string(),
            other => format!("method 0x{other:03x}"),
        }
    }
}

/// TURN `Allocate`, the method that asks a relay for an address.
pub const METHOD_ALLOCATE: u16 = 0x003;

/// The application data inside a TURN **ChannelData** wrapper, or `None` if
/// this is not one.
///
/// # Why unwrapping matters
///
/// Media relayed through TURN arrives wrapped: the RTP an endpoint sent is not
/// the first byte of the datagram, it sits four bytes in, behind a channel
/// number and a length. A reader that does not unwrap it sees no RTP at all,
/// and a call whose audio went through a relay therefore reports as a call with
/// NO MEDIA — which is the same thing sipnab says about a call that genuinely
/// carried nothing. Those are opposite findings and they were rendered
/// identically.
pub fn channel_data_payload(payload: &[u8]) -> Option<&[u8]> {
    if !is_channel_data(payload) {
        return None;
    }
    let declared = u16::from_be_bytes([payload[2], payload[3]]) as usize;
    payload.get(4..4 + declared)
}

/// Whether a payload is a TURN **ChannelData** message rather than anything
/// STUN-shaped.
///
/// This is the one part of TURN the STUN parser genuinely cannot reach.
/// ChannelData has no magic cookie and no transaction ID — it is a 4-byte
/// header (a channel number, then a length) wrapping raw application data, so
/// `parse` rejects it and is right to.
///
/// It is still identifiable, and worth identifying, because the three
/// multiplexed protocols occupy disjoint high bits: STUN's top two bits are
/// `00`, a ChannelData channel number is `0x4000..=0x7FFF` (`01`), and RTP's
/// version field is `10`. So media relayed through TURN can be told apart from
/// media sent directly, which is otherwise indistinguishable from a capture
/// holding no media at all.
pub fn is_channel_data(payload: &[u8]) -> bool {
    if payload.len() < 4 {
        return false;
    }
    let channel = u16::from_be_bytes([payload[0], payload[1]]);
    if !(0x4000..=0x7FFF).contains(&channel) {
        return false;
    }
    // The declared length must fit what is present, allowing for the 4-byte
    // header. Over UDP the padding to a 4-byte boundary is not sent on the
    // final message, so this is a floor rather than an equality.
    let declared = u16::from_be_bytes([payload[2], payload[3]]) as usize;
    payload.len() >= 4 + declared
}

/// Parse a UDP payload as STUN, or `None` if it is not one.
///
/// # Why this is safe to run over arbitrary UDP
///
/// The magic cookie is checked before any attribute is read, and every length
/// is bounds-checked against what is actually present rather than trusted. A
/// payload that is not STUN fails at the cookie; a payload that claims to be
/// STUN and lies about its lengths yields `None` or a message with the
/// attributes that did fit, never a panic and never a read past the buffer.
pub fn parse(payload: &[u8]) -> Option<StunMessage> {
    if payload.len() < 20 {
        return None;
    }
    let cookie = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
    if cookie != MAGIC_COOKIE {
        return None;
    }
    // The two most significant bits of a STUN message are always zero, which is
    // what lets STUN share a port with RTP (whose version bits are 0b10).
    let raw_type = u16::from_be_bytes([payload[0], payload[1]]);
    if raw_type & 0xC000 != 0 {
        return None;
    }

    let class = match (raw_type & 0x0100 != 0, raw_type & 0x0010 != 0) {
        (false, false) => StunClass::Request,
        (false, true) => StunClass::Indication,
        (true, false) => StunClass::SuccessResponse,
        (true, true) => StunClass::ErrorResponse,
    };
    // RFC 5389 §6: the method is split around the class bits.
    let method = ((raw_type & 0x3E00) >> 2) | ((raw_type & 0x00E0) >> 1) | (raw_type & 0x000F);

    let mut transaction_id = [0u8; 12];
    transaction_id.copy_from_slice(&payload[8..20]);

    let declared = u16::from_be_bytes([payload[2], payload[3]]) as usize;
    // Trust the buffer, not the header: a truncated capture routinely holds a
    // shorter body than the header claims, and a snaplen is the usual reason.
    let body_end = 20usize.saturating_add(declared).min(payload.len());
    let mut body = &payload[20..body_end];

    let mut msg = StunMessage {
        class,
        method,
        transaction_id,
        mapped_address: None,
        error_code: None,
        software: None,
        relayed_address: None,
        peer_address: None,
        lifetime: None,
        realm: None,
        nonce_present: false,
        alternate_server: None,
        use_candidate: false,
        priority: None,
        ice_role: None,
        channel_number: None,
        requested_transport: None,
        mapped_address_is_xor: false,
        fingerprint_valid: None,
    };

    // Attributes: 2-byte type, 2-byte length, value, padded to 4 bytes.
    while body.len() >= 4 {
        // Where this attribute starts within the whole message, which is what
        // FINGERPRINT's CRC span is defined against.
        let attr_start = payload.len() - body.len();
        let attr_type = u16::from_be_bytes([body[0], body[1]]);
        let attr_len = u16::from_be_bytes([body[2], body[3]]) as usize;
        let value_end = 4usize.saturating_add(attr_len);
        if value_end > body.len() {
            break; // truncated attribute: keep what was read, stop here
        }
        let value = &body[4..value_end];
        match attr_type {
            0x0020 => {
                // Unconditional, unlike the legacy arm below: if both are
                // present the XOR form wins whichever order they arrive in.
                if let Some(a) = xor_mapped_address(value, &transaction_id) {
                    msg.mapped_address = Some(a);
                    msg.mapped_address_is_xor = true;
                }
            }
            // MAPPED-ADDRESS, the pre-RFC5389 form, NOT XOR'd. Servers that
            // predate the cookie still answer with it, and RFC 5389 servers
            // often send both. Taken only when the XOR form has not already
            // been read: that one is the answer a NAT cannot rewrite on the
            // way back, which is the whole reason the XOR form exists.
            0x0001 if !msg.mapped_address_is_xor => {
                msg.mapped_address = plain_address(value);
            }
            // ALTERNATE-SERVER is a plain address too: it is not obfuscated,
            // because it names a server rather than the client's own address.
            0x8023 => msg.alternate_server = plain_address(value),
            0x0014 => {
                msg.realm = Some(
                    String::from_utf8_lossy(value)
                        .trim_matches(|c: char| c.is_whitespace() || c == '\0')
                        .to_string(),
                );
            }
            0x0015 => msg.nonce_present = true,
            // ICE (RFC 8445). Reported, never acted on: these say what the
            // agents decided, and sipnab's job is to show that decision.
            0x0025 => msg.use_candidate = true,
            0x0024 if value.len() >= 4 => {
                msg.priority = Some(u32::from_be_bytes([value[0], value[1], value[2], value[3]]));
            }
            0x802A => msg.ice_role = Some(IceRole::Controlling),
            0x8029 => msg.ice_role = Some(IceRole::Controlled),
            // TURN channel and transport: what a relay path is made of.
            0x000C if value.len() >= 2 => {
                msg.channel_number = Some(u16::from_be_bytes([value[0], value[1]]));
            }
            0x0019 if !value.is_empty() => msg.requested_transport = Some(value[0]),
            // FINGERPRINT (RFC 5389 §15.5): CRC-32 of everything preceding
            // this attribute, XOR 0x5354554e. `attr_start` is where this
            // attribute begins in the whole message, which is exactly the
            // span the CRC covers.
            0x8028 if value.len() >= 4 => {
                let claimed = u32::from_be_bytes([value[0], value[1], value[2], value[3]]);
                let covered = &payload[..attr_start];
                msg.fingerprint_valid = Some(crc32_ieee(covered) ^ 0x5354_554e == claimed);
            }
            // TURN attributes. Same XOR scheme as XOR-MAPPED-ADDRESS, which is
            // why they share the decoder rather than getting a second copy.
            0x0016 => msg.relayed_address = xor_mapped_address(value, &transaction_id),
            0x0012 => msg.peer_address = xor_mapped_address(value, &transaction_id),
            0x000D if value.len() >= 4 => {
                msg.lifetime = Some(u32::from_be_bytes([value[0], value[1], value[2], value[3]]));
            }
            0x0009 if value.len() >= 4 => {
                // Class in byte 2 (low 3 bits), number in byte 3.
                let class_digit = u16::from(value[2] & 0x07);
                msg.error_code = Some(class_digit * 100 + u16::from(value[3]));
            }
            0x8022 => {
                // Trailing NULs, not just whitespace. Real phones declare a
                // SOFTWARE length that includes their own NUL padding — seen on
                // a field capture where a 20-byte value held an 18-byte string
                // plus two NULs — and `trim` alone leaves them in, so the name
                // renders with `\0\0` glued to it wherever it is shown.
                msg.software = Some(
                    String::from_utf8_lossy(value)
                        .trim_matches(|c: char| c.is_whitespace() || c == '\0')
                        .to_string(),
                )
            }
            _ => {}
        }
        // Attributes are padded to a 4-byte boundary; the padding is not
        // included in the declared length.
        let advance = value_end.next_multiple_of(4).min(body.len());
        if advance == 0 {
            break;
        }
        body = &body[advance..];
    }

    Some(msg)
}

/// CRC-32 (IEEE 802.3), for `FINGERPRINT`.
///
/// Written out rather than pulled in as a dependency: it is fifteen lines, it
/// is used in exactly one place, and a checksum whose polynomial is visible in
/// the source is one a reader can check against the RFC without leaving the
/// file.
fn crc32_ieee(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for b in data {
        crc ^= u32::from(*b);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

/// Decode a plain (non-XOR) address attribute: `MAPPED-ADDRESS` and
/// `ALTERNATE-SERVER` share the layout, minus the obfuscation.
fn plain_address(value: &[u8]) -> Option<SocketAddr> {
    if value.len() < 4 {
        return None;
    }
    let port = u16::from_be_bytes([value[2], value[3]]);
    match value[1] {
        0x01 if value.len() >= 8 => Some(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(value[4], value[5], value[6], value[7])),
            port,
        )),
        0x02 if value.len() >= 20 => {
            let mut o = [0u8; 16];
            o.copy_from_slice(&value[4..20]);
            Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(o)), port))
        }
        _ => None,
    }
}

/// Decode `XOR-MAPPED-ADDRESS` (RFC 5389 §15.2), whose address is XOR'd with
/// the cookie — and, for IPv6, with the transaction ID as well.
///
/// The obfuscation exists because some NATs rewrite anything that looks like an
/// address in a payload, and would have corrupted the very answer being
/// reported.
fn xor_mapped_address(value: &[u8], transaction_id: &[u8; 12]) -> Option<SocketAddr> {
    if value.len() < 4 {
        return None;
    }
    let family = value[1];
    let port = u16::from_be_bytes([value[2], value[3]]) ^ ((MAGIC_COOKIE >> 16) as u16);
    let cookie = MAGIC_COOKIE.to_be_bytes();
    match family {
        0x01 if value.len() >= 8 => {
            let mut octets = [0u8; 4];
            for i in 0..4 {
                octets[i] = value[4 + i] ^ cookie[i];
            }
            Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(octets)), port))
        }
        0x02 if value.len() >= 20 => {
            let mut octets = [0u8; 16];
            for i in 0..16 {
                let key = if i < 4 {
                    cookie[i]
                } else {
                    transaction_id[i - 4]
                };
                octets[i] = value[4 + i] ^ key;
            }
            Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A Binding Request in the shape field captures actually carry, including
    /// the SOFTWARE quirk that broke the first version of this parser: a
    /// declared length covering the vendor's own NUL padding.
    ///
    /// The bytes are synthetic. The structure is what was observed on a real
    /// capture; the transaction ID and addresses are not, because a capture's
    /// identifiers do not belong in source.
    pub(super) const FIELD_SHAPED_REQUEST: [u8; 44] = [
        0x00, 0x01, 0x00, 0x18, // Binding Request, 24 bytes of attributes
        0x21, 0x12, 0xa4, 0x42, // magic cookie
        0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, // txn id
        0x80, 0x22, 0x00, 0x14, // SOFTWARE, 20 bytes
        // "example-stack 1.0" + two NULs inside the declared 20-byte length.
        0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2d, 0x73, 0x74, 0x61, 0x63, 0x6b, 0x20, 0x31,
        0x2e, 0x30, 0x00, 0x00, 0x00,
    ];

    #[test]
    fn a_field_shaped_binding_request_parses() {
        let msg = parse(&FIELD_SHAPED_REQUEST).expect("a real STUN request must parse");
        assert_eq!(msg.class, StunClass::Request);
        assert_eq!(msg.method, 0x001, "Binding");
        assert!(msg.is_binding_request());
        assert_eq!(
            msg.transaction_id,
            [
                0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac
            ]
        );
        assert_eq!(
            msg.software.as_deref(),
            Some("example-stack 1.0"),
            "the vendor's NUL padding must not survive into the name"
        );
        assert_eq!(msg.mapped_address, None, "a request carries no answer");
    }

    /// Anything without the cookie is not STUN, however plausible its first
    /// two bytes are. This is what makes it safe to offer every UDP payload.
    #[test]
    fn a_payload_without_the_cookie_is_not_stun() {
        assert!(parse(b"INVITE sip:alice@example.com SIP/2.0\r\n").is_none());
        assert!(parse(&[0u8; 64]).is_none());
        assert!(parse(&[]).is_none());
        // RTP: version bits 0b10 set the two high bits, which STUN never has.
        let mut rtp = [0u8; 32];
        rtp[0] = 0x80;
        rtp[1] = 0x00;
        rtp[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
        assert!(
            parse(&rtp).is_none(),
            "an RTP packet that happens to carry the cookie bytes is still RTP"
        );
    }

    /// A success response yields the reflexive address, un-XOR'd.
    #[test]
    fn a_success_response_yields_the_mapped_address() {
        let txn = [0x11u8; 12];
        let mut m = Vec::new();
        m.extend_from_slice(&0x0101u16.to_be_bytes()); // Binding success
        m.extend_from_slice(&12u16.to_be_bytes()); // one 12-byte attribute
        m.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        m.extend_from_slice(&txn);
        m.extend_from_slice(&0x0020u16.to_be_bytes()); // XOR-MAPPED-ADDRESS
        m.extend_from_slice(&8u16.to_be_bytes());
        m.push(0);
        m.push(0x01); // IPv4
        let port: u16 = 54321;
        m.extend_from_slice(&(port ^ ((MAGIC_COOKIE >> 16) as u16)).to_be_bytes());
        let ip = Ipv4Addr::new(203, 0, 113, 7);
        let cookie = MAGIC_COOKIE.to_be_bytes();
        for (i, o) in ip.octets().iter().enumerate() {
            m.push(o ^ cookie[i]);
        }

        let msg = parse(&m).expect("parses");
        assert_eq!(msg.class, StunClass::SuccessResponse);
        assert_eq!(
            msg.mapped_address,
            Some(SocketAddr::new(IpAddr::V4(ip), port)),
            "the whole point of the response is this address"
        );
    }

    /// A lying length must not read past the buffer, and must not panic. A
    /// capture snaplen produces exactly this shape routinely.
    #[test]
    fn a_truncated_or_lying_message_yields_no_panic() {
        let mut m = FIELD_SHAPED_REQUEST.to_vec();
        // Claim far more body than is present.
        m[2] = 0xff;
        m[3] = 0xff;
        let msg = parse(&m).expect("header is still valid");
        assert!(msg.is_binding_request());

        // Truncate mid-attribute at every point and require termination.
        for cut in 20..FIELD_SHAPED_REQUEST.len() {
            let _ = parse(&FIELD_SHAPED_REQUEST[..cut]);
        }
    }

    /// An error response reports the code rather than reading as silence.
    #[test]
    fn an_error_response_carries_its_code() {
        let mut m = Vec::new();
        m.extend_from_slice(&0x0111u16.to_be_bytes()); // Binding error
        m.extend_from_slice(&8u16.to_be_bytes());
        m.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        m.extend_from_slice(&[0x22u8; 12]);
        m.extend_from_slice(&0x0009u16.to_be_bytes()); // ERROR-CODE
        m.extend_from_slice(&4u16.to_be_bytes());
        m.extend_from_slice(&[0x00, 0x00, 0x04, 0x01]); // class 4, number 1 => 401
        let msg = parse(&m).expect("parses");
        assert_eq!(msg.class, StunClass::ErrorResponse);
        assert_eq!(msg.error_code, Some(401));
    }
}

// ── Unanswered-request tracking ─────────────────────────────────────

/// One Binding Request that was sent and never answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnansweredRequest {
    /// Who asked.
    pub from: SocketAddr,
    /// Which server was asked.
    pub to: SocketAddr,
    /// How many times the same transaction was sent. A retransmission is the
    /// endpoint's own evidence that it did not get an answer, so counting them
    /// separates "one lost packet" from "the server is not there".
    pub attempts: u32,
    /// The `SOFTWARE` the asker named itself as, when it did.
    pub software: Option<String>,
    /// Which question went unanswered — `Binding` (nobody told the endpoint
    /// its own address) or `Allocate` (the relay would not give it one).
    /// Reported because the two are fixed in different places: a Binding
    /// failure points at the STUN server or the path to it, an Allocate
    /// failure at the TURN relay's credentials, quota or reachability.
    pub method: String,
}

/// Requests seen, keyed by transaction ID, with their answers struck off.
#[derive(Debug, Default)]
struct Tracker {
    /// Outstanding requests. An answer removes its entry, so what remains at
    /// the end of a capture is exactly the set that went unanswered.
    pending: HashMap<[u8; 12], UnansweredRequest>,
    /// Answers that were AUTHENTICATION challenges rather than plain
    /// refusals. See `note_message`.
    challenged: u64,
    /// Requests that WERE answered, counted only. Kept because "3 of 40 went
    /// unanswered" and "3 of 3" are different findings, and a bare list of
    /// three cannot tell them apart.
    answered: u64,
}

/// Process-global, for the same reason the capture-quality counters are: the
/// pipeline sees packets one at a time and the report is assembled at the end.
static TRACKER: Mutex<Option<Tracker>> = Mutex::new(None);

/// Record one observed STUN message.
///
/// A request is remembered; a response of either kind strikes its transaction
/// off. Repeating a transaction ID counts an attempt rather than adding a
/// second entry — a phone that retries five times has one unanswered question,
/// not five.
pub fn note_message(msg: &StunMessage, src: SocketAddr, dst: SocketAddr) {
    let Ok(mut guard) = TRACKER.lock() else {
        return; // a poisoned lock must not take the capture down
    };
    let tracker = guard.get_or_insert_with(Tracker::default);
    match msg.class {
        StunClass::Request => {
            // Binding and Allocate: the two requests whose silence ends in the
            // same symptom. The other TURN methods are deliberately not tracked
            // — a CreatePermission or ChannelBind rides an allocation that has
            // already succeeded, so its silence is a consequence rather than a
            // cause, and reporting it would bury the request that actually
            // failed under the ones that followed it.
            if !msg.is_binding_request() && !msg.is_allocate_request() {
                return;
            }
            tracker
                .pending
                .entry(msg.transaction_id)
                .and_modify(|e| e.attempts += 1)
                .or_insert(UnansweredRequest {
                    from: src,
                    to: dst,
                    attempts: 1,
                    software: msg.software.clone(),
                    method: msg.method_name(),
                });
        }
        StunClass::SuccessResponse | StunClass::ErrorResponse => {
            // An ERROR response is still an answer: the server was reachable
            // and said no, which is a different fault from silence and must not
            // be reported as one.
            if tracker.pending.remove(&msg.transaction_id).is_some() {
                tracker.answered += 1;
                if msg.is_auth_challenge() {
                    // Counted apart because it is the most actionable answer of
                    // all: the path works and the credentials are the problem,
                    // which sends the operator somewhere completely different
                    // from a dropped-packet hunt.
                    tracker.challenged += 1;
                }
            }
        }
        StunClass::Indication => {}
    }
}

/// How many answers were authentication challenges.
pub fn auth_challenges() -> u64 {
    TRACKER
        .lock()
        .ok()
        .and_then(|g| g.as_ref().map(|t| t.challenged))
        .unwrap_or(0)
}

/// Binding Requests that never got an answer, busiest first, with the number
/// that DID get one for scale.
pub fn unanswered_requests() -> (Vec<UnansweredRequest>, u64) {
    let Ok(guard) = TRACKER.lock() else {
        return (Vec::new(), 0);
    };
    let Some(tracker) = guard.as_ref() else {
        return (Vec::new(), 0);
    };
    let mut out: Vec<UnansweredRequest> = tracker.pending.values().cloned().collect();
    // Most-retried first, then by address so two runs over one capture print
    // the same order.
    out.sort_by(|a, b| {
        b.attempts
            .cmp(&a.attempts)
            .then_with(|| a.from.to_string().cmp(&b.from.to_string()))
    });
    (out, tracker.answered)
}

/// Clear the tracker, for a process that analyses several captures in sequence
/// and for tests that assert on exact counts.
pub fn reset() {
    if let Ok(mut guard) = TRACKER.lock() {
        *guard = None;
    }
}

#[cfg(test)]
mod turn_tests {
    use super::*;

    /// The tracker is process-global, so the two tests that assert on its exact
    /// contents must not run at the same time — one's `reset` is the other's
    /// missing request. Same reason the capture-drop counters serialize.
    static TRACKER_LOCK: Mutex<()> = Mutex::new(());

    fn message(msg_type: u16, txn: [u8; 12], attrs: &[(u16, Vec<u8>)]) -> Vec<u8> {
        let mut body = Vec::new();
        for (t, v) in attrs {
            body.extend_from_slice(&t.to_be_bytes());
            body.extend_from_slice(&(v.len() as u16).to_be_bytes());
            body.extend_from_slice(v);
            while body.len() % 4 != 0 {
                body.push(0);
            }
        }
        let mut m = Vec::new();
        m.extend_from_slice(&msg_type.to_be_bytes());
        m.extend_from_slice(&(body.len() as u16).to_be_bytes());
        m.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        m.extend_from_slice(&txn);
        m.extend_from_slice(&body);
        m
    }

    fn xor_v4(ip: [u8; 4], port: u16) -> Vec<u8> {
        let cookie = MAGIC_COOKIE.to_be_bytes();
        let mut v = vec![0, 0x01];
        v.extend_from_slice(&(port ^ ((MAGIC_COOKIE >> 16) as u16)).to_be_bytes());
        for (i, o) in ip.iter().enumerate() {
            v.push(o ^ cookie[i]);
        }
        v
    }

    /// TURN reuses the STUN framing, so an Allocate parses without the parser
    /// knowing TURN exists — but its METHOD must be identified, because an
    /// unanswered Allocate is a different fault from an unanswered Binding.
    #[test]
    fn an_allocate_request_is_identified_as_turn_not_binding() {
        let m = message(0x0003, [0x01; 12], &[]);
        let msg = parse(&m).expect("TURN shares the STUN header, so this parses");
        assert_eq!(msg.class, StunClass::Request);
        assert!(msg.is_allocate_request());
        assert!(
            !msg.is_binding_request(),
            "Allocate must not be counted as a Binding: they fail for different reasons"
        );
        assert_eq!(msg.method_name(), "Allocate");
    }

    /// The relayed address is the TURN answer an endpoint advertises, so it
    /// must survive the same XOR decoding as XOR-MAPPED-ADDRESS.
    #[test]
    fn an_allocate_response_yields_the_relayed_address() {
        let m = message(
            0x0103, // Allocate success
            [0x02; 12],
            &[
                (0x0016, xor_v4([198, 51, 100, 20], 49160)),
                (0x000D, 600u32.to_be_bytes().to_vec()),
            ],
        );
        let msg = parse(&m).expect("parses");
        assert_eq!(msg.method_name(), "Allocate");
        assert_eq!(
            msg.relayed_address.map(|a| a.to_string()),
            Some("198.51.100.20:49160".to_string())
        );
        assert_eq!(msg.lifetime, Some(600));
    }

    /// ChannelData is the one TURN framing the STUN parser cannot read, and it
    /// must be told apart from both STUN and RTP by its high bits alone.
    #[test]
    fn channel_data_is_recognised_and_never_confused_with_stun_or_rtp() {
        let mut cd = vec![0x40, 0x01, 0x00, 0x04];
        cd.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        assert!(is_channel_data(&cd));
        assert!(
            parse(&cd).is_none(),
            "ChannelData has no cookie, so the STUN parser must decline it"
        );

        // RTP: version bits 0b10 put it above the ChannelData range.
        let mut rtp = vec![0x80, 0x00, 0x00, 0x10];
        rtp.extend_from_slice(&[0u8; 16]);
        assert!(!is_channel_data(&rtp), "RTP is not ChannelData");

        // A STUN request starts 0x00 and is likewise outside the range.
        assert!(!is_channel_data(&FIELD_SHAPED_REQUEST_FOR_CD()));
    }

    #[allow(non_snake_case)]
    fn FIELD_SHAPED_REQUEST_FOR_CD() -> Vec<u8> {
        message(0x0001, [0x03; 12], &[])
    }

    /// A response strikes its request off; silence leaves it standing. Both
    /// directions asserted, because a tracker that never records and a tracker
    /// that never clears both report zero unanswered on a healthy capture.
    #[test]
    fn an_answered_request_is_struck_off_and_an_unanswered_one_stands() {
        let _guard = TRACKER_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset();
        let src: SocketAddr = "192.0.2.10:5060".parse().unwrap();
        let dst: SocketAddr = "198.51.100.1:3478".parse().unwrap();

        let asked = parse(&message(0x0001, [0xAA; 12], &[])).unwrap();
        let ignored = parse(&message(0x0001, [0xBB; 12], &[])).unwrap();
        note_message(&asked, src, dst);
        note_message(&ignored, src, dst);
        // The ignored one is retransmitted: one question, two attempts.
        note_message(&ignored, src, dst);

        let answer = parse(&message(0x0101, [0xAA; 12], &[])).unwrap();
        note_message(&answer, dst, src);

        let (unanswered, answered) = unanswered_requests();
        assert_eq!(answered, 1, "the answered transaction must be counted");
        assert_eq!(unanswered.len(), 1, "exactly one question went unanswered");
        assert_eq!(
            unanswered[0].attempts, 2,
            "a retransmission is not a second question"
        );
        assert_eq!(unanswered[0].method, "Binding");
        reset();
    }

    /// An ERROR response is an ANSWER. The server was reachable and said no,
    /// which is a different fault from silence and points somewhere else — so
    /// it must not be reported as unanswered.
    #[test]
    fn an_error_response_counts_as_answered() {
        let _guard = TRACKER_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset();
        let src: SocketAddr = "192.0.2.10:5060".parse().unwrap();
        let dst: SocketAddr = "198.51.100.1:3478".parse().unwrap();
        let asked = parse(&message(0x0001, [0xCC; 12], &[])).unwrap();
        note_message(&asked, src, dst);
        let refused = parse(&message(
            0x0111,
            [0xCC; 12],
            &[(0x0009, vec![0, 0, 0x04, 0x01])],
        ))
        .unwrap();
        assert_eq!(refused.error_code, Some(401));
        note_message(&refused, dst, src);

        let (unanswered, answered) = unanswered_requests();
        assert!(
            unanswered.is_empty(),
            "a refusal is an answer; reporting it as silence sends the operator \
             looking for a blocked path that is not there"
        );
        assert_eq!(answered, 1);
        reset();
    }
}

#[cfg(test)]
mod channel_unwrap_tests {
    use super::*;

    /// The RTP inside a ChannelData wrapper must come back out, or a relayed
    /// call reports as having no media — indistinguishable from a call that
    /// carried none.
    #[test]
    fn the_media_inside_a_channel_wrapper_is_recovered() {
        // A minimal RTP packet: version 2, PT 0, seq 1.
        let mut rtp = vec![0x80, 0x00, 0x00, 0x01];
        rtp.extend_from_slice(&[0x00, 0x00, 0x10, 0x00]); // timestamp
        rtp.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]); // ssrc
        rtp.extend_from_slice(&[0xaa; 160]); // payload

        let mut wrapped = vec![0x40, 0x01];
        wrapped.extend_from_slice(&(rtp.len() as u16).to_be_bytes());
        wrapped.extend_from_slice(&rtp);

        let inner = channel_data_payload(&wrapped).expect("a wrapper must unwrap");
        assert_eq!(
            inner,
            &rtp[..],
            "the recovered bytes must be the RTP verbatim"
        );
        // And the unwrapped bytes must look like RTP to the rest of the stack.
        assert_eq!(inner[0] >> 6, 2, "RTP version 2 survives the unwrap");
    }

    /// Anything that is not a wrapper yields nothing, so this cannot invent a
    /// payload out of ordinary media or signaling.
    #[test]
    fn nothing_else_unwraps() {
        assert!(channel_data_payload(b"INVITE sip:a@b SIP/2.0\r\n").is_none());
        let mut rtp = vec![0x80, 0x00, 0x00, 0x01];
        rtp.extend_from_slice(&[0u8; 20]);
        assert!(
            channel_data_payload(&rtp).is_none(),
            "plain RTP is not wrapped"
        );
        assert!(
            channel_data_payload(&[0x40, 0x01, 0xff, 0xff, 0x00]).is_none(),
            "a wrapper claiming more than it holds yields nothing rather than a short read"
        );
    }
}

#[cfg(test)]
mod attribute_coverage_tests {
    use super::*;

    fn msg(msg_type: u16, attrs: &[(u16, Vec<u8>)]) -> Vec<u8> {
        let mut body = Vec::new();
        for (t, v) in attrs {
            body.extend_from_slice(&t.to_be_bytes());
            body.extend_from_slice(&(v.len() as u16).to_be_bytes());
            body.extend_from_slice(v);
            while body.len() % 4 != 0 {
                body.push(0);
            }
        }
        let mut m = Vec::new();
        m.extend_from_slice(&msg_type.to_be_bytes());
        m.extend_from_slice(&(body.len() as u16).to_be_bytes());
        m.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        m.extend_from_slice(&[0x5a; 12]);
        m.extend_from_slice(&body);
        m
    }

    /// A 401 with a REALM is an AUTHENTICATION challenge, not a blocked path.
    /// Without the realm the two read alike, and they are fixed in different
    /// places: one needs credentials, the other needs a firewall rule.
    #[test]
    fn an_auth_challenge_is_distinguishable_from_a_blocked_path() {
        let m = msg(
            0x0111, // Binding error
            &[
                (0x0009, vec![0, 0, 0x04, 0x01]),       // ERROR-CODE 401
                (0x0014, b"example.org".to_vec()),      // REALM
                (0x0015, b"dcd98b7102dd2f0e".to_vec()), // NONCE
            ],
        );
        let parsed = parse(&m).expect("parses");
        assert_eq!(parsed.error_code, Some(401));
        assert_eq!(parsed.realm.as_deref(), Some("example.org"));
        assert!(parsed.nonce_present, "a nonce means a challenge to answer");
        assert!(
            parsed.is_auth_challenge(),
            "401 plus a realm is a challenge, and must not read as silence"
        );
    }

    /// A 400 is not a challenge: no realm, nothing to answer.
    #[test]
    fn a_plain_error_is_not_an_auth_challenge() {
        let m = msg(0x0111, &[(0x0009, vec![0, 0, 0x04, 0x00])]);
        let parsed = parse(&m).expect("parses");
        assert_eq!(parsed.error_code, Some(400));
        assert!(!parsed.is_auth_challenge());
        assert_eq!(parsed.realm, None);
    }

    /// Legacy MAPPED-ADDRESS: pre-RFC5389 servers still answer with it, and
    /// without it a SUCCESSFUL response reads as "no address returned".
    #[test]
    fn a_legacy_mapped_address_is_still_an_answer() {
        // Not XOR'd: family 0x01, port and address in the clear.
        let mut v = vec![0, 0x01];
        v.extend_from_slice(&8080u16.to_be_bytes());
        v.extend_from_slice(&[203, 0, 113, 9]);
        let m = msg(0x0101, &[(0x0001, v)]);
        let parsed = parse(&m).expect("parses");
        assert_eq!(
            parsed.mapped_address.map(|a| a.to_string()),
            Some("203.0.113.9:8080".to_string()),
            "a legacy server's answer must not read as no answer at all"
        );
    }

    /// XOR-MAPPED-ADDRESS wins when both are present: RFC 5389 servers send
    /// both for compatibility, and the XOR one is the one NAT cannot corrupt.
    #[test]
    fn the_xor_form_wins_when_both_are_present() {
        let cookie = MAGIC_COOKIE.to_be_bytes();
        let mut xor = vec![0, 0x01];
        xor.extend_from_slice(&(9000u16 ^ ((MAGIC_COOKIE >> 16) as u16)).to_be_bytes());
        for (i, o) in [198u8, 51, 100, 7].iter().enumerate() {
            xor.push(o ^ cookie[i]);
        }
        let mut legacy = vec![0, 0x01];
        legacy.extend_from_slice(&8080u16.to_be_bytes());
        legacy.extend_from_slice(&[203, 0, 113, 9]);

        let m = msg(0x0101, &[(0x0001, legacy), (0x0020, xor)]);
        let parsed = parse(&m).expect("parses");
        assert_eq!(
            parsed.mapped_address.map(|a| a.to_string()),
            Some("198.51.100.7:9000".to_string()),
            "the XOR form is the one a NAT cannot rewrite, so it must win"
        );
    }

    /// ALTERNATE-SERVER: a redirect, which without parsing reads as a failure.
    #[test]
    fn a_redirect_names_where_it_points() {
        let mut v = vec![0, 0x01];
        v.extend_from_slice(&3478u16.to_be_bytes());
        v.extend_from_slice(&[192, 0, 2, 50]);
        let m = msg(0x0111, &[(0x0009, vec![0, 0, 0x03, 0x00]), (0x8023, v)]);
        let parsed = parse(&m).expect("parses");
        assert_eq!(parsed.error_code, Some(300));
        assert_eq!(
            parsed.alternate_server.map(|a| a.to_string()),
            Some("192.0.2.50:3478".to_string()),
            "a redirect that does not name its target reads as a dead end"
        );
    }
}

#[cfg(test)]
mod fingerprint_tests {
    use super::*;

    /// FINGERPRINT is CRC-32 of the message XOR 0x5354554e, over a header
    /// whose length field counts the attribute itself. Verifiable with NO
    /// credentials, which is what separates it from MESSAGE-INTEGRITY.
    fn with_fingerprint(msg_type: u16, mut body: Vec<u8>) -> Vec<u8> {
        let mut m = Vec::new();
        // Length must already include the 8-byte FINGERPRINT attribute.
        let total = body.len() + 8;
        m.extend_from_slice(&msg_type.to_be_bytes());
        m.extend_from_slice(&(total as u16).to_be_bytes());
        m.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        m.extend_from_slice(&[0x77; 12]);
        m.append(&mut body);
        let crc = crc32(&m) ^ 0x5354_554e;
        m.extend_from_slice(&0x8028u16.to_be_bytes());
        m.extend_from_slice(&4u16.to_be_bytes());
        m.extend_from_slice(&crc.to_be_bytes());
        m
    }

    /// Reference CRC-32 (IEEE), so the test does not depend on the parser's.
    fn crc32(data: &[u8]) -> u32 {
        let mut crc = 0xFFFF_FFFFu32;
        for b in data {
            crc ^= u32::from(*b);
            for _ in 0..8 {
                crc = if crc & 1 != 0 {
                    (crc >> 1) ^ 0xEDB8_8320
                } else {
                    crc >> 1
                };
            }
        }
        !crc
    }

    /// A correct fingerprint verifies, and that is a claim sipnab can honestly
    /// make: it needs no key, so it is not the unverifiable case.
    #[test]
    fn a_correct_fingerprint_verifies() {
        let m = with_fingerprint(0x0001, Vec::new());
        let parsed = parse(&m).expect("parses");
        assert_eq!(
            parsed.fingerprint_valid,
            Some(true),
            "a fingerprint sipnab can check must report as checked and good"
        );
    }

    /// A corrupted one reports FALSE, not None. None means "absent"; false
    /// means "present and wrong", and conflating them would turn a corrupt
    /// message into a message with nothing to say.
    #[test]
    fn a_corrupt_fingerprint_reports_false_not_absent() {
        let mut m = with_fingerprint(0x0001, Vec::new());
        let n = m.len();
        m[n - 1] ^= 0xFF;
        let parsed = parse(&m).expect("parses");
        assert_eq!(parsed.fingerprint_valid, Some(false));
    }

    /// No FINGERPRINT at all is None: sipnab did not check, and must not imply
    /// it did.
    #[test]
    fn an_absent_fingerprint_is_none() {
        let parsed = parse(&super::tests::FIELD_SHAPED_REQUEST).expect("parses");
        assert_eq!(parsed.fingerprint_valid, None);
    }
}

#[cfg(test)]
mod ice_and_turn_attribute_tests {
    use super::*;

    fn msg(msg_type: u16, attrs: &[(u16, Vec<u8>)]) -> Vec<u8> {
        let mut body = Vec::new();
        for (t, v) in attrs {
            body.extend_from_slice(&t.to_be_bytes());
            body.extend_from_slice(&(v.len() as u16).to_be_bytes());
            body.extend_from_slice(v);
            while body.len() % 4 != 0 {
                body.push(0);
            }
        }
        let mut m = Vec::new();
        m.extend_from_slice(&msg_type.to_be_bytes());
        m.extend_from_slice(&(body.len() as u16).to_be_bytes());
        m.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        m.extend_from_slice(&[0x31; 12]);
        m.extend_from_slice(&body);
        m
    }

    /// USE-CANDIDATE is the nomination: it says THIS pair is the one media
    /// will use. Without it a capture of a working ICE exchange and a capture
    /// of one that never converged look the same.
    #[test]
    fn a_nominated_candidate_is_reported() {
        let m = msg(
            0x0001,
            &[
                (0x0025, Vec::new()),
                (0x0024, 0x7E00_00FFu32.to_be_bytes().to_vec()),
            ],
        );
        let parsed = parse(&m).expect("parses");
        assert!(parsed.use_candidate, "the nomination is the whole finding");
        assert_eq!(parsed.priority, Some(0x7E00_00FF));
    }

    /// The controlling/controlled roles say which side drives nomination, and
    /// a capture where BOTH claim controlling is a role conflict -- a real
    /// misconfiguration that otherwise shows up only as media never starting.
    #[test]
    fn the_ice_role_is_reported_for_both_sides() {
        let controlling = parse(&msg(0x0001, &[(0x802A, vec![0; 8])])).expect("parses");
        assert_eq!(controlling.ice_role, Some(IceRole::Controlling));
        let controlled = parse(&msg(0x0001, &[(0x8029, vec![0; 8])])).expect("parses");
        assert_eq!(controlled.ice_role, Some(IceRole::Controlled));
        let neither = parse(&msg(0x0001, &[])).expect("parses");
        assert_eq!(neither.ice_role, None, "not an ICE exchange, so no role");
    }

    /// TURN CHANNEL-NUMBER and REQUESTED-TRANSPORT explain a relay path: which
    /// channel carries the media, and over what transport it was asked for.
    #[test]
    fn turn_channel_and_transport_are_reported() {
        let m = msg(
            0x0009, // ChannelBind
            &[
                (0x000C, vec![0x40, 0x02, 0, 0]), // CHANNEL-NUMBER 0x4002
                (0x0019, vec![17, 0, 0, 0]),      // REQUESTED-TRANSPORT UDP
            ],
        );
        let parsed = parse(&m).expect("parses");
        assert_eq!(parsed.method_name(), "ChannelBind");
        assert_eq!(parsed.channel_number, Some(0x4002));
        assert_eq!(parsed.requested_transport, Some(17), "17 is UDP");
    }
}
