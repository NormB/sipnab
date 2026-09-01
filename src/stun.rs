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
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IceRole {
    /// This agent picks the pair. `ICE-CONTROLLING` (0x802A).
    Controlling,
    /// This agent accepts the other's choice. `ICE-CONTROLLED` (0x8029).
    Controlled,
}

impl IceRole {
    /// The role in the words RFC 8445 uses for it, for a report a human
    /// reads. One place rather than a `Debug` cast at each surface, which is
    /// how `Controlling` reached operator-facing output with a capital C.
    pub fn label(self) -> &'static str {
        match self {
            Self::Controlling => "controlling",
            Self::Controlled => "controlled",
        }
    }
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
    /// TURN `REQUESTED-ADDRESS-FAMILY` (0x0017): `0x01` IPv4, `0x02` IPv6.
    ///
    /// Reported because asking for a family the relay cannot allocate draws a
    /// `440`, and on a dual-stack network that is an allocation failure whose
    /// only other symptom is media that never starts.
    pub requested_address_family: Option<u8>,
    /// TURN `EVEN-PORT` (0x0018), as the R bit alone.
    ///
    /// `Some(true)` asks the server to reserve the next-higher port as well,
    /// which is how a client asks for the RFC 3550 RTP/RTCP port pair;
    /// `Some(false)` asks only that the relayed port be even. `None` means the
    /// attribute was absent, which is a different claim from either.
    pub even_port: Option<bool>,
    /// TURN `DONT-FRAGMENT` (0x001a): the client asked the relay to set DF on
    /// relayed datagrams. A zero-length flag, so presence is the whole value.
    pub dont_fragment: bool,
    /// TURN `RESERVATION-TOKEN` (0x0022): the token claiming a port that an
    /// earlier `EVEN-PORT` allocation reserved.
    pub reservation_token: Option<u64>,
    /// TURN `DATA` (0x0013): where the relayed payload sits WITHIN the payload
    /// this message was parsed from, as a byte range.
    ///
    /// A range rather than a copy, because the payload is a whole relayed RTP
    /// packet and the caller already owns the buffer it came in — handing back
    /// offsets lets it re-slice its own `Bytes` with no allocation.
    ///
    /// Decoded but deliberately not yet consumed: unwrapping relayed media out
    /// of Send and Data indications is the pre-channel twin of what
    /// [`channel_data_payload`] does for ChannelData, and it is a separate
    /// change from decoding the attribute. Locating it is what makes that
    /// change a pipeline edit rather than a parser one.
    pub data: Option<std::ops::Range<usize>>,
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

/// TURN `Refresh`, the method that extends an allocation — or releases it
/// outright with a `LIFETIME` of zero.
pub const METHOD_REFRESH: u16 = 0x004;

/// TURN `ChannelBind`, the method that binds a channel number to a peer.
///
/// The one message that names both halves of a relayed media path, and it
/// names them in the REQUEST — the success response carries neither. That is
/// why the binding is folded in from the transaction rather than from the
/// response (`Tracker::apply_turn_response`, private — see its comment).
pub const METHOD_CHANNEL_BIND: u16 = 0x009;

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
    channel_data_payload_framed(payload, ChannelDataFraming::Datagram)
}

/// How the enclosing transport delimits a ChannelData frame.
///
/// The distinction is not cosmetic: it is the whole of what separates a real
/// relay frame from a stray datagram whose first two bytes happened to land in
/// the channel-number window. See [`is_channel_data_framed`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelDataFraming {
    /// UDP: one frame per datagram. RFC 5766 §11.5 makes the padding to a
    /// four-byte boundary optional over a datagram transport, so the frame is
    /// required to end either exactly at the data or exactly at the padded end
    /// of it — and either way to account for the WHOLE datagram.
    Datagram,
    /// TCP or TLS: frames are concatenated on a byte stream, so every frame is
    /// padded to a four-byte boundary and more data may follow it.
    Stream,
}

/// [`channel_data_payload`], told how the transport delimits the frame.
pub fn channel_data_payload_framed(payload: &[u8], framing: ChannelDataFraming) -> Option<&[u8]> {
    if !is_channel_data_framed(payload, framing) {
        return None;
    }
    let declared = u16::from_be_bytes([payload[2], payload[3]]) as usize;
    payload.get(4..4 + declared)
}

/// Whether a payload is a TURN **ChannelData** message rather than anything
/// STUN-shaped, assuming the datagram framing UDP gives it.
///
/// See [`is_channel_data_framed`] for what is checked and why.
pub fn is_channel_data(payload: &[u8]) -> bool {
    is_channel_data_framed(payload, ChannelDataFraming::Datagram)
}

/// Whether a payload is a TURN **ChannelData** message rather than anything
/// STUN-shaped, given how its transport delimits a frame.
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
///
/// # Why the length must account for the WHOLE datagram
///
/// The high bits alone are sixteen thousand of the sixty-five thousand values
/// a first-two-byte pair can take: one arbitrary UDP payload in four lands in
/// the window. This check used to accept `payload.len() >= 4 + declared` — a
/// floor — so a stray datagram in the window carrying any small length field
/// passed, and the pipeline then RE-CLASSIFIED whatever the first four bytes
/// happened to precede. That is the same false-positive class that turned
/// Windows LLMNR queries into phantom RTP streams, arrived at from the other
/// side.
///
/// Requiring the frame to account for the entire datagram (padded or not, per
/// RFC 5766 §11.5) removes it by construction: a stray packet now has to land
/// in the window AND carry a length field that describes its own size. A
/// declared length of zero is refused for the same reason — it is the one
/// shape where any four-byte datagram in the window would otherwise satisfy
/// every check, and a relay frame carrying no application data is not
/// something a TURN client sends.
///
/// Upstream's recursion-terminates reasoning is unaffected and strengthened:
/// the unwrapped payload is `declared` bytes out of a datagram of at least
/// `4 + declared`, so it is still strictly shorter than the frame that carried
/// it — and now it is strictly shorter by at least four bytes rather than
/// possibly by zero.
pub fn is_channel_data_framed(payload: &[u8], framing: ChannelDataFraming) -> bool {
    if payload.len() < 4 {
        return false;
    }
    let channel = u16::from_be_bytes([payload[0], payload[1]]);
    if !(0x4000..=0x7FFF).contains(&channel) {
        return false;
    }
    let declared = u16::from_be_bytes([payload[2], payload[3]]) as usize;
    if declared == 0 {
        return false;
    }
    let unpadded = 4 + declared;
    let padded = 4 + declared.next_multiple_of(4);
    match framing {
        // One frame per datagram, with the optional padding either present in
        // full or absent — never a frame that leaves bytes unaccounted for.
        ChannelDataFraming::Datagram => payload.len() == unpadded || payload.len() == padded,
        // On a byte stream the padding is mandatory and the next frame may
        // follow, so what is required is that the padded frame FITS.
        ChannelDataFraming::Stream => payload.len() >= padded,
    }
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
        requested_address_family: None,
        even_port: None,
        dont_fragment: false,
        reservation_token: None,
        data: None,
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
            // REQUESTED-ADDRESS-FAMILY: which family the relayed address
            // should be. A family the relay cannot allocate draws a 440, and
            // on a dual-stack network that is an allocation failure whose only
            // other symptom is media that never starts.
            0x0017 if !value.is_empty() => msg.requested_address_family = Some(value[0]),
            // EVEN-PORT: the R bit is the most significant bit of the single
            // value byte. Recorded as the bit rather than as presence, because
            // "an even port" and "an even port with its pair reserved" are
            // different asks and the second is what an RTP/RTCP pair needs.
            0x0018 if !value.is_empty() => msg.even_port = Some(value[0] & 0x80 != 0),
            // DONT-FRAGMENT: zero-length by definition, so presence is the
            // value and there is nothing to bounds-check.
            0x001a => msg.dont_fragment = true,
            // RESERVATION-TOKEN: 64 bits, and refused rather than padded when
            // short, for the reason LIFETIME is — a token read from four bytes
            // is not the token the sender sent.
            0x0022 if value.len() >= 8 => {
                let mut t = [0u8; 8];
                t.copy_from_slice(&value[..8]);
                msg.reservation_token = Some(u64::from_be_bytes(t));
            }
            // DATA: the relayed payload of a Send or Data indication. Located,
            // never copied — see the field docs. `attr_start` is where this
            // attribute's type field begins in the whole payload, so the value
            // begins four bytes later. An empty DATA relays nothing and stays
            // `None`, so a caller never re-slices a zero-length range.
            0x0013 if !value.is_empty() => {
                let start = attr_start + 4;
                msg.data = Some(start..start + attr_len);
            }
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
            // LIFETIME. The length guard is load-bearing rather than defensive:
            // a short value falls through to the catch-all and stays `None`,
            // which is refusal. Zero-extending two bytes into a u32 would
            // invent a short expiry the sender never claimed — and an expiry is
            // exactly what [`TurnAllocation::expired_before_last_activity`]
            // draws a conclusion from.
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

// ── Transaction, allocation and unanswered-request tracking ─────────

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

/// One STUN or TURN transaction: a request, however many times it was sent,
/// and the answer if one ever came.
///
/// The richer sibling of [`UnansweredRequest`], which is a projection of this.
/// Both exist because they answer different questions: `UnansweredRequest` is
/// "what got no reply", which every surface already reports, while this is
/// "what the exchange achieved" — the reflexive or relayed address a server
/// handed back, and when. That second question is what
/// [`crate::rtp::diagnosis`] needs to connect a failed probe to a call, and it
/// cannot be answered from a list of failures alone.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct StunTransaction {
    /// The 96-bit transaction ID, hex-encoded for display and JSON.
    pub transaction_id: String,
    /// The socket the request left from. On a response whose request predates
    /// the capture, the socket the response was sent TO.
    pub client: SocketAddr,
    /// The socket the request was sent to.
    pub server: SocketAddr,
    /// Method number: `0x001` Binding, `0x003` Allocate, and so on.
    pub method: u16,
    /// The method's name, rendered once at insertion because it is what both
    /// the table and the NDJSON print.
    pub method_name: String,
    /// Timestamp of the first request seen for this transaction.
    pub first_request: chrono::DateTime<chrono::Utc>,
    /// Timestamp of the most recent request seen.
    pub last_request: chrono::DateTime<chrono::Utc>,
    /// How many requests were seen. Greater than one means retransmission,
    /// which by itself proves the earlier attempts went unanswered. Zero means
    /// only the response was captured.
    pub request_count: u32,
    /// When a response arrived, if one did.
    pub responded_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Round-trip time from the last request to the response, in milliseconds.
    pub rtt_ms: Option<f64>,
    /// The reflexive address the server reported back.
    pub mapped_address: Option<SocketAddr>,
    /// The relayed transport address a TURN server allocated.
    pub relayed_address: Option<SocketAddr>,
    /// The peer a CreatePermission, ChannelBind or Send concerns.
    pub peer_address: Option<SocketAddr>,
    /// `LIFETIME` in seconds, from an Allocate or Refresh.
    pub lifetime_secs: Option<u32>,
    /// `CHANNEL-NUMBER` from a ChannelBind request.
    pub channel_number: Option<u16>,
    /// The error code an error response carried.
    pub error_code: Option<u16>,
    /// Whether the answer was an AUTHENTICATION challenge rather than a
    /// refusal — see [`StunMessage::is_auth_challenge`].
    pub auth_challenge: bool,
    /// The client's `SOFTWARE` string, when it advertised one.
    pub software: Option<String>,
    /// Which role the requester claimed, when it claimed one.
    pub ice_role: Option<IceRole>,
    /// Whether any message in this transaction nominated its candidate pair.
    pub use_candidate: bool,
    /// The `PRIORITY` the request carried, when it carried one.
    ///
    /// Kept because it is half of what separates an ICE CONNECTIVITY CHECK
    /// from a plain server-reflexive probe: RFC 8445 §7.2.1 requires a check
    /// to carry `PRIORITY` and a role attribute, and a Binding Request sent to
    /// a STUN server to learn a reflexive address carries neither. See
    /// [`Self::is_ice_check`] — without that discriminator, "ICE never
    /// completed" and "the STUN server did not answer" are the same sentence,
    /// and they are fixed in different places.
    pub priority: Option<u32>,
    /// Whether a `FINGERPRINT` was checked, and whether it held.
    ///
    /// `Some(false)` is the reportable state: a message that carried a
    /// fingerprint and got it wrong. `None` means nobody checked, and must
    /// never render as a failure.
    pub fingerprint_valid: Option<bool>,
}

impl StunTransaction {
    /// Whether this transaction never received a response.
    pub fn is_unanswered(&self) -> bool {
        self.responded_at.is_none()
    }

    /// Whether the client had to retransmit, which means at least one request
    /// went unanswered even if a later one succeeded.
    pub fn was_retransmitted(&self) -> bool {
        self.request_count > 1
    }

    /// Whether this is one of the two requests whose SILENCE is a reportable
    /// fault: `Binding` (nobody told the endpoint its own address) or
    /// `Allocate` (the relay would not give it one).
    ///
    /// The other TURN methods are deliberately excluded. A CreatePermission or
    /// ChannelBind rides an allocation that already succeeded, so its silence
    /// is a consequence rather than a cause, and reporting it would bury the
    /// request that actually failed under the ones that followed it.
    pub fn silence_is_a_fault(&self) -> bool {
        self.method == 0x001 || self.method == METHOD_ALLOCATE
    }

    /// Whether this is an ICE CONNECTIVITY CHECK rather than a plain
    /// server-reflexive probe.
    ///
    /// RFC 8445 §7.2.1 requires a check to carry `PRIORITY` and one of
    /// `ICE-CONTROLLING`/`ICE-CONTROLLED`; a Binding Request aimed at a STUN
    /// server carries neither. That is the whole discriminator, and it needs
    /// no SDP to apply — which matters, because the two failures look
    /// identical in a transaction table and are fixed in different places.
    ///
    /// `USE-CANDIDATE` alone qualifies: a nomination is a check by
    /// definition, whatever else the message carried.
    pub fn is_ice_check(&self) -> bool {
        self.method == 0x001
            && (self.priority.is_some() || self.ice_role.is_some() || self.use_candidate)
    }

    /// Whether this check nominated its candidate pair AND the peer agreed.
    ///
    /// Both halves are required. A `USE-CANDIDATE` that drew no reply
    /// nominated nothing — the pair was never validated — and an error
    /// response is a refusal rather than an agreement. Reporting either as
    /// the path media took would name a path that carried none.
    pub fn nominated_pair(&self) -> bool {
        self.use_candidate
            && self.method == 0x001
            && self.responded_at.is_some()
            && self.error_code.is_none()
    }
}

/// One TURN channel, and the media that crossed it.
///
/// # Why an allocation has to record this
///
/// ChannelData is unwrapped and the RTP inside reaches the stream store as an
/// ordinary stream, which is the whole point — otherwise a relayed call
/// reports as a call with no media. But the stream that comes out is addressed
/// CLIENT-to-RELAY, so nothing in it says it was relayed, which channel
/// carried it, or which allocation it belonged to.
///
/// The cost of not recording it was not cosmetic. An allocation that lapsed
/// mid-call could be reported as lapsed and could not name one packet that
/// died with it — so the one finding sipnab makes that has no other symptom
/// anywhere also had no evidence attached to it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct RelayChannel {
    /// The channel number, always within `0x4000..=0x7FFF`.
    pub channel: u16,
    /// The peer this channel was bound to, when a ChannelBind for it was seen
    /// to succeed.
    ///
    /// `None` on a capture that started after the bind. Absent means unknown,
    /// never "no peer": the frames still attribute to the allocation, and the
    /// far side of the relay is simply not in this file.
    pub peer: Option<SocketAddr>,
    /// Whether a ChannelBind for this channel was SEEN to succeed here.
    ///
    /// Separates a channel this capture watched being set up from one inferred
    /// from its frames alone. The second is not a fault — a capture that
    /// starts mid-call is the ordinary case — and rendering it as one would
    /// blame the client for when the capture began.
    pub bound: bool,
    /// Relayed frames seen on this channel.
    pub frames: u64,
    /// Relayed application bytes across them, the four-byte framing excluded.
    pub bytes: u64,
    /// When the first frame on this channel was seen.
    pub first_seen: chrono::DateTime<chrono::Utc>,
    /// When the most recent one was.
    pub last_seen: chrono::DateTime<chrono::Utc>,
    /// RTP SSRCs observed inside this channel's frames, first-seen order,
    /// capped at [`MAX_SSRCS_PER_CHANNEL`].
    ///
    /// This is the join to the stream store: a stream carries an SSRC and a
    /// socket pair, and so does a channel — so a relayed stream can be told
    /// which allocation carried it without the media path having to know that
    /// TURN exists. See [`relay_path_for`].
    pub ssrcs: Vec<u32>,
    /// SSRCs beyond the cap. Exact where [`Self::ssrcs`] is not, so a report
    /// can say the list is a sample instead of implying it is the whole of it.
    pub ssrcs_dropped: u32,
}

/// A TURN allocation: a relayed transport address with a lifetime.
///
/// Keyed by the client/server socket pair rather than by transaction ID,
/// because the Refresh that keeps it alive is a DIFFERENT transaction from the
/// Allocate that created it — and the whole reason to track an allocation is
/// to see whether those refreshes kept up.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct TurnAllocation {
    /// The client socket that holds the allocation.
    pub client: SocketAddr,
    /// The TURN server socket that granted it.
    pub server: SocketAddr,
    /// The relayed transport address the server allocated, when the success
    /// response carried one.
    pub relayed_address: Option<SocketAddr>,
    /// Lifetime in seconds as most recently granted.
    pub lifetime_secs: Option<u32>,
    /// When the allocation was first seen granted.
    pub allocated_at: chrono::DateTime<chrono::Utc>,
    /// When it was most recently refreshed, if it ever was.
    pub refreshed_at: Option<chrono::DateTime<chrono::Utc>>,
    /// How many Refresh transactions succeeded.
    pub refreshes: u32,
    /// The most recent traffic seen on this client/server pair — a STUN
    /// message or a relayed ChannelData frame. What the expiry is measured
    /// against.
    pub last_activity: chrono::DateTime<chrono::Utc>,
    /// Whether the client released it explicitly (a Refresh with `LIFETIME` 0).
    pub released: bool,
    /// The channels seen on this allocation and the media that crossed them,
    /// capped at [`MAX_CHANNELS_PER_ALLOCATION`].
    pub channels: Vec<RelayChannel>,
    /// Relayed frames on this allocation whose channel was not retained,
    /// because [`MAX_CHANNELS_PER_ALLOCATION`] was already full.
    ///
    /// Counted in FRAMES rather than in channels because frames are what can
    /// be counted exactly: knowing how many DISTINCT channels were shed would
    /// need a record of every channel number ever seen, which is the unbounded
    /// table the cap exists to prevent. Non-zero means [`Self::channels`] is a
    /// sample of what crossed this allocation, and every surface that prints
    /// the channels says so when it is.
    pub unattributed_frames: u64,
}

impl TurnAllocation {
    /// When this allocation lapses, given the last lifetime the server granted
    /// and the last refresh observed.
    pub fn expires_at(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        let secs = self.lifetime_secs?;
        let from = self.refreshed_at.unwrap_or(self.allocated_at);
        from.checked_add_signed(chrono::TimeDelta::seconds(i64::from(secs)))
    }

    /// Whether traffic was still using this allocation after the point the
    /// last observed grant could have sustained it.
    ///
    /// The operational shape of a call that dies partway through: the client
    /// stopped refreshing (or its Refresh never reached the server), the
    /// server tore the allocation down, and the media stopped with it — with
    /// no SIP message anywhere to explain why. Stated as "no Refresh was seen"
    /// rather than "no Refresh was sent", because a capture that started late
    /// or missed a packet cannot tell those apart.
    ///
    /// A deliberate release (`LIFETIME` 0) is never this: the client asked for
    /// the teardown, so the teardown is not a fault.
    pub fn expired_before_last_activity(&self) -> bool {
        if self.released {
            return false;
        }
        self.expires_at()
            .is_some_and(|expiry| expiry < self.last_activity)
    }

    /// How long traffic continued past the expiry, in seconds, or `None` when
    /// no lifetime was ever granted.
    pub fn seconds_past_expiry(&self) -> Option<i64> {
        let expiry = self.expires_at()?;
        Some((self.last_activity - expiry).num_seconds())
    }

    /// Relayed frames across every channel on this allocation.
    pub fn relayed_frames(&self) -> u64 {
        self.channels.iter().map(|c| c.frames).sum()
    }

    /// Every SSRC observed crossing this allocation, first-seen order, with
    /// duplicates across channels removed.
    ///
    /// The answer to "what media dies when this allocation lapses", which is
    /// the question the lapsed-allocation finding could not previously answer.
    pub fn relayed_ssrcs(&self) -> Vec<u32> {
        let mut out: Vec<u32> = Vec::new();
        for channel in &self.channels {
            for ssrc in &channel.ssrcs {
                if !out.contains(ssrc) {
                    out.push(*ssrc);
                }
            }
        }
        out
    }

    /// One line naming the media this allocation carried, or `None` when no
    /// relayed frame was ever seen on it.
    ///
    /// `None` rather than "0 streams" on purpose: an allocation with no
    /// relayed frames in the capture is the ordinary shape of a call that was
    /// set up and not yet talking, and printing a zero beside it would read as
    /// a second fault.
    pub fn relayed_media_label(&self) -> Option<String> {
        if self.channels.is_empty() {
            return None;
        }
        let ssrcs = self.relayed_ssrcs();
        let channels: Vec<String> = self
            .channels
            .iter()
            .map(|c| format!("0x{:04x}", c.channel))
            .collect();
        let mut label = format!(
            "{} frame(s) on channel {}",
            self.relayed_frames(),
            channels.join(", ")
        );
        if !ssrcs.is_empty() {
            let named: Vec<String> = ssrcs.iter().map(|s| format!("0x{s:08x}")).collect();
            label.push_str(&format!(
                ", carrying {} stream(s) (SSRC {})",
                named.len(),
                named.join(", ")
            ));
        }
        let shed_ssrcs: u32 = self.channels.iter().map(|c| c.ssrcs_dropped).sum();
        if self.unattributed_frames > 0 || shed_ssrcs > 0 {
            label.push_str(&format!(
                " (a sample: {} frame(s) crossed channels beyond the retention cap, and {} \
                 further SSRC(s) were not retained)",
                self.unattributed_frames, shed_ssrcs
            ));
        }
        Some(label)
    }

    /// The entry for `channel`, created if this allocation has room for it.
    ///
    /// `None` when [`MAX_CHANNELS_PER_ALLOCATION`] is already full and this
    /// channel is new — the caller counts the frame against
    /// [`Self::unattributed_frames`] rather than growing the table (D17).
    fn channel_entry(
        &mut self,
        channel: u16,
        timestamp: chrono::DateTime<chrono::Utc>,
    ) -> Option<&mut RelayChannel> {
        // Two passes rather than one `if let ... else`: the borrow from the
        // first would still be live across the push, which the borrow checker
        // refuses even though the paths are disjoint.
        if let Some(index) = self.channels.iter().position(|c| c.channel == channel) {
            return self.channels.get_mut(index);
        }
        if self.channels.len() >= MAX_CHANNELS_PER_ALLOCATION {
            return None;
        }
        self.channels.push(RelayChannel {
            channel,
            peer: None,
            bound: false,
            frames: 0,
            bytes: 0,
            first_seen: timestamp,
            last_seen: timestamp,
            ssrcs: Vec::new(),
            ssrcs_dropped: 0,
        });
        self.channels.last_mut()
    }
}

/// Transaction retention cap. STUN transactions are short-lived and small;
/// this is generous for an ICE-heavy capture while staying far below the point
/// where the map costs meaningful memory (D17 — every store is bounded).
pub const MAX_TRANSACTIONS: usize = 10_000;

/// Allocation retention cap. One entry per client/server socket pair.
pub const MAX_ALLOCATIONS: usize = 2_048;

/// Channels retained per allocation (D17 — every store is bounded).
///
/// Sixteen: RFC 5766 gives a client 16,384 channel numbers, and a real
/// endpoint binds one per media stream — two for an audio call with RTCP
/// multiplexed off, a handful for video. A capture that needs more than
/// sixteen on ONE allocation is a load generator, and the exact totals stay on
/// [`RelayChannel::ssrcs_dropped`] and [`TurnAllocation::unattributed_frames`]
/// where the cap does bite.
pub const MAX_CHANNELS_PER_ALLOCATION: usize = 16;

/// SSRCs retained per channel (D17).
///
/// A channel carries one media stream in the ordinary case; eight leaves room
/// for an endpoint that re-keys its SSRC mid-call without letting a
/// misbehaving one grow the table without bound.
pub const MAX_SSRCS_PER_CHANNEL: usize = 8;

/// Requests seen, keyed by transaction ID, with their answers folded in.
#[derive(Debug, Default)]
struct Tracker {
    /// Every transaction in insertion order, so eviction is oldest-first
    /// rather than arbitrary. An answer folds into its entry rather than
    /// removing it: what went unanswered is a QUERY over this table, and
    /// keeping the answered ones is what lets a report say "3 of 40" instead
    /// of listing three failures with no scale.
    transactions: indexmap::IndexMap<[u8; 12], StunTransaction>,
    /// Transactions evicted to stay inside [`MAX_TRANSACTIONS`].
    dropped: u64,
    /// TURN allocations, keyed by the client/server socket pair.
    allocations: indexmap::IndexMap<(SocketAddr, SocketAddr), TurnAllocation>,
    /// Allocations evicted to stay inside [`MAX_ALLOCATIONS`].
    allocations_dropped: u64,
    /// STUN messages processed, including retransmissions and the ones whose
    /// transaction was later evicted. Exact where `transactions` is capped.
    packets: u64,
    /// Indications processed. Counted rather than tracked: RFC 5766 §10 sends
    /// them fire-and-forget, so a transaction row for one would read as a
    /// failure that never happened.
    indications: u64,
    /// Relayed ChannelData frames seen. Not STUN messages, and counted apart
    /// from them for that reason.
    channel_data_frames: u64,
    /// Relayed application bytes across those frames, framing excluded.
    channel_data_bytes: u64,
}

/// Process-global, for the same reason the capture-quality counters are: the
/// pipeline sees packets one at a time and the report is assembled at the end.
///
/// And for one more, which `--cores` makes unavoidable: a NAT-discovery
/// probe's host pair is (client, STUN server), never the pair of the SIP
/// dialog the probe was run for. Per-worker state would file the evidence
/// under a worker holding none of the calls it explains.
static TRACKER: Mutex<Option<Tracker>> = Mutex::new(None);

/// Whether any STUN message has been recorded, readable without the lock.
///
/// The fast path for [`transactions_from`], which the media diagnosis calls
/// once per dialog that advertised an unroutable address — a shape that is
/// EVERY dialog on a LAN-only capture. A run that saw no STUN answers with one
/// relaxed load and never takes the mutex.
static STUN_SEEN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Whether any TURN allocation has been granted, readable without the lock.
///
/// The hot-path guard for [`note_channel_data`], which fires once per relayed
/// MEDIA packet rather than once per signaling packet. A capture with no TURN
/// allocation in it — which is every capture that never touched a relay —
/// answers with one relaxed load and never takes the mutex.
static ALLOCATION_SEEN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Record one observed STUN message.
///
/// A request is remembered; a response of either kind folds its answer into
/// the transaction it belongs to. Repeating a transaction ID counts an attempt
/// rather than adding a second entry — a phone that retries five times has one
/// unanswered question, not five.
pub fn note_message(
    msg: &StunMessage,
    src: SocketAddr,
    dst: SocketAddr,
    timestamp: chrono::DateTime<chrono::Utc>,
) {
    let Ok(mut guard) = TRACKER.lock() else {
        return; // a poisoned lock must not take the capture down
    };
    let tracker = guard.get_or_insert_with(Tracker::default);
    tracker.packets += 1;
    // Release, paired with the Acquire in `transactions_from`: the insertion
    // below must be visible to any thread that observes the flag.
    STUN_SEEN.store(true, std::sync::atomic::Ordering::Release);
    match msg.class {
        StunClass::Request => {
            tracker.touch_allocation(src, dst, timestamp);
            if let Some(tx) = tracker.transactions.get_mut(&msg.transaction_id) {
                tx.request_count += 1;
                tx.last_request = timestamp;
                return;
            }
            tracker.evict_transaction_if_full();
            let tx = StunTransaction {
                transaction_id: hex_transaction_id(&msg.transaction_id),
                client: src,
                server: dst,
                method: msg.method,
                method_name: msg.method_name(),
                first_request: timestamp,
                last_request: timestamp,
                request_count: 1,
                responded_at: None,
                rtt_ms: None,
                mapped_address: None,
                relayed_address: None,
                peer_address: msg.peer_address,
                lifetime_secs: msg.lifetime,
                channel_number: msg.channel_number,
                error_code: None,
                auth_challenge: false,
                software: msg.software.clone(),
                ice_role: msg.ice_role,
                use_candidate: msg.use_candidate,
                priority: msg.priority,
                fingerprint_valid: msg.fingerprint_valid,
            };
            tracker.transactions.insert(msg.transaction_id, tx);
        }
        StunClass::SuccessResponse | StunClass::ErrorResponse => {
            tracker.touch_allocation(src, dst, timestamp);
            // On a response the server is the source and the client the
            // destination — the mirror of a request.
            if let Some(tx) = tracker.transactions.get_mut(&msg.transaction_id) {
                // An ERROR response is still an ANSWER: the server was
                // reachable and said no, which is a different fault from
                // silence and must not be reported as one.
                if tx.responded_at.is_none() {
                    tx.responded_at = Some(timestamp);
                    tx.rtt_ms = Some(
                        (timestamp - tx.last_request)
                            .num_microseconds()
                            .unwrap_or(0) as f64
                            / 1000.0,
                    );
                }
                if msg.mapped_address.is_some() {
                    tx.mapped_address = msg.mapped_address;
                }
                if msg.relayed_address.is_some() {
                    tx.relayed_address = msg.relayed_address;
                }
                if msg.lifetime.is_some() {
                    tx.lifetime_secs = msg.lifetime;
                }
                if msg.error_code.is_some() {
                    tx.error_code = msg.error_code;
                }
                tx.auth_challenge |= msg.is_auth_challenge();
                if msg.fingerprint_valid.is_some() {
                    tx.fingerprint_valid = msg.fingerprint_valid;
                }
            } else {
                // A response whose request predates the capture. Filed as
                // answered with no request count, so it neither vanishes nor
                // reads as a failure.
                tracker.evict_transaction_if_full();
                let tx = StunTransaction {
                    transaction_id: hex_transaction_id(&msg.transaction_id),
                    client: dst,
                    server: src,
                    method: msg.method,
                    method_name: msg.method_name(),
                    first_request: timestamp,
                    last_request: timestamp,
                    request_count: 0,
                    responded_at: Some(timestamp),
                    rtt_ms: None,
                    mapped_address: msg.mapped_address,
                    relayed_address: msg.relayed_address,
                    peer_address: msg.peer_address,
                    lifetime_secs: msg.lifetime,
                    channel_number: msg.channel_number,
                    error_code: msg.error_code,
                    auth_challenge: msg.is_auth_challenge(),
                    software: msg.software.clone(),
                    ice_role: msg.ice_role,
                    use_candidate: msg.use_candidate,
                    priority: msg.priority,
                    fingerprint_valid: msg.fingerprint_valid,
                };
                tracker.transactions.insert(msg.transaction_id, tx);
            }
            tracker.apply_turn_response(msg, src, dst, timestamp);
        }
        StunClass::Indication => {
            tracker.indications += 1;
            tracker.touch_allocation(src, dst, timestamp);
        }
    }
}

/// Record one relayed TURN ChannelData frame, given the WHOLE frame.
///
/// The whole frame rather than a length, because the header is where the
/// attribution lives: the channel number is the first two bytes, and the RTP
/// inside carries the SSRC that joins this frame to the stream the media path
/// built out of it. A caller handing over a byte count could not supply
/// either, and one handing over both separately could get them out of step.
/// Only the relayed application data is counted as media — the four-byte
/// header is framing, and counting it would overstate the media.
///
/// Two things are recorded, and they answer different questions:
///
/// * The allocation's activity clock, which is what
///   [`TurnAllocation::expired_before_last_activity`] measures the expiry
///   against — relayed media IS the traffic that kept flowing past it, and an
///   allocation whose clock only ever advanced on signaling could never show
///   a relay torn down under a live call.
/// * The channel this frame crossed and the SSRC inside it, which is what
///   lets a stream in the stream store be told which relay carried it. See
///   [`RelayChannel`] and [`relay_path_for`].
///
/// # Cost
///
/// This is the one entry point here that fires per MEDIA packet, so it is
/// guarded by a relaxed atomic: until a TURN allocation has actually been
/// granted there is nothing for a frame to advance, and the mutex is never
/// taken. A capture that never touched a relay pays one load per relayed
/// frame, and a capture with no relayed frames pays nothing at all.
pub fn note_channel_data(
    src: SocketAddr,
    dst: SocketAddr,
    frame: &[u8],
    timestamp: chrono::DateTime<chrono::Utc>,
) {
    if !ALLOCATION_SEEN.load(std::sync::atomic::Ordering::Acquire) {
        return;
    }
    let Some(payload) = channel_data_payload(frame) else {
        return; // not a ChannelData frame: nothing to attribute
    };
    // Safe: `channel_data_payload` already required at least four bytes.
    let channel = u16::from_be_bytes([frame[0], frame[1]]);
    let ssrc = relayed_ssrc(payload);
    let bytes = payload.len();
    let Ok(mut guard) = TRACKER.lock() else {
        return;
    };
    let tracker = guard.get_or_insert_with(Tracker::default);
    tracker.channel_data_frames += 1;
    tracker.channel_data_bytes += bytes as u64;
    tracker.touch_allocation(src, dst, timestamp);
    tracker.record_relayed_frame(src, dst, channel, bytes as u64, ssrc, timestamp);
}

/// The SSRC of an RTP packet relayed inside a ChannelData frame, or `None`
/// when the payload is not one.
///
/// Written here rather than borrowed from [`crate::rtp`] deliberately: this
/// module must not start deciding what IS media. All it needs is the join key
/// the stream store will end up filing this packet under, and it is better to
/// return `None` on anything ambiguous than to record an SSRC read out of
/// something that turns out not to be RTP at all.
///
/// RTCP is excluded on the same reasoning. It shares the version bits, its
/// packet types land at `72..=79` once the marker bit is masked off, and its
/// bytes 8..12 are not an SSRC in the sense the stream store means — folding
/// them in would file a report block under a media stream that never existed.
fn relayed_ssrc(payload: &[u8]) -> Option<u32> {
    if payload.len() < 12 || payload[0] & 0xC0 != 0x80 {
        return None;
    }
    if (72..=79).contains(&(payload[1] & 0x7F)) {
        return None; // RTCP, not a media stream
    }
    Some(u32::from_be_bytes([
        payload[8],
        payload[9],
        payload[10],
        payload[11],
    ]))
}

/// The relay a stream's packets crossed, or `None` when they crossed none.
///
/// # How a relayed stream reaches its allocation
///
/// The join is the socket pair plus the SSRC, and both halves are needed. A
/// relayed stream's 5-tuple is CLIENT-to-RELAY — that is where the packets
/// were actually seen — which is exactly the allocation's own key, so the pair
/// finds the allocation in either direction. The SSRC then picks out which
/// channel on it carried this particular stream, because one allocation
/// routinely carries several.
///
/// A stream whose SSRC was never seen inside a ChannelData frame is NOT
/// attributed to the allocation its addresses happen to match. Media sent
/// directly to a relay's address without being channel-wrapped is a different
/// thing from media the relay carried, and claiming the second would be the
/// confident wrong answer this whole join exists to avoid.
///
/// Answered from a relaxed atomic, with no lock taken, on any run that never
/// saw a TURN allocation granted — which is every capture without a relay.
pub fn relay_path_for(a: SocketAddr, b: SocketAddr, ssrc: u32) -> Option<RelayPath> {
    if !ALLOCATION_SEEN.load(std::sync::atomic::Ordering::Acquire) {
        return None;
    }
    let guard = TRACKER.lock().ok()?;
    let tracker = guard.as_ref()?;
    let alloc = tracker
        .allocations
        .get(&(a, b))
        .or_else(|| tracker.allocations.get(&(b, a)))?;
    let channel = alloc.channels.iter().find(|c| c.ssrcs.contains(&ssrc))?;
    Some(RelayPath {
        client: alloc.client,
        server: alloc.server,
        relayed_address: alloc.relayed_address,
        channel: channel.channel,
        peer: channel.peer,
        lapsed: alloc.expired_before_last_activity(),
    })
}

/// The relay one media stream crossed: which allocation, which channel, and
/// whether that allocation had already lapsed under it.
///
/// Context rather than a finding. It answers "where did this call's audio
/// actually go", which for a relayed call had no answer at all — the stream
/// list showed packets between the phone and a relay, and nothing anywhere
/// said the relay was one, which address it was relaying to, or that the
/// allocation carrying it was about to be torn down.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct RelayPath {
    /// The client socket that holds the allocation.
    pub client: SocketAddr,
    /// The TURN server socket that granted it.
    pub server: SocketAddr,
    /// The relayed transport address the server allocated — the address the
    /// far end of the call actually sends to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relayed_address: Option<SocketAddr>,
    /// The channel number that carried this stream.
    pub channel: u16,
    /// The peer the channel was bound to, when the bind was seen.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer: Option<SocketAddr>,
    /// Whether the allocation was still carrying traffic past the lifetime it
    /// was last granted.
    ///
    /// Carried here, on the stream's own record, because that is where it is
    /// actionable: the capture-level finding says an allocation lapsed, and
    /// this says THIS call's audio was on it.
    pub lapsed: bool,
}

impl Tracker {
    /// Drop the oldest transaction when the table is at capacity.
    fn evict_transaction_if_full(&mut self) {
        if self.transactions.len() >= MAX_TRANSACTIONS {
            self.transactions.shift_remove_index(0);
            self.dropped += 1;
        }
    }

    /// Fold a TURN success response into the allocation table.
    fn apply_turn_response(
        &mut self,
        msg: &StunMessage,
        src: SocketAddr,
        dst: SocketAddr,
        timestamp: chrono::DateTime<chrono::Utc>,
    ) {
        if msg.class != StunClass::SuccessResponse {
            return;
        }
        let (client, server) = (dst, src);
        match msg.method {
            METHOD_ALLOCATE => self.upsert_allocation(client, server, timestamp, |alloc| {
                if msg.relayed_address.is_some() {
                    alloc.relayed_address = msg.relayed_address;
                }
                if msg.lifetime.is_some() {
                    alloc.lifetime_secs = msg.lifetime;
                }
            }),
            METHOD_REFRESH => self.upsert_allocation(client, server, timestamp, |alloc| {
                alloc.refreshes += 1;
                alloc.refreshed_at = Some(timestamp);
                if msg.lifetime.is_some() {
                    alloc.lifetime_secs = msg.lifetime;
                }
                // LIFETIME 0 is how RFC 5766 §7 releases an allocation. A
                // released allocation is not an expired one.
                if msg.lifetime == Some(0) {
                    alloc.released = true;
                }
            }),
            // ChannelBind is the one message that names both halves of a
            // relayed media path — and it names them in the REQUEST, not in
            // the response, which carries no attributes at all. So the
            // binding is read back off the transaction this response just
            // answered, and only once it HAS been answered: a ChannelBind
            // that drew nothing bound no channel, and recording it would put
            // a peer on a path the relay never agreed to carry.
            //
            // This is the one place besides Allocate that may CREATE an
            // allocation, and it is entitled to: RFC 5766 §11 has a relay
            // refuse a ChannelBind that names no allocation, so a successful
            // one proves the allocation exists even on a capture that started
            // after the Allocate. Nothing is invented by it — no relayed
            // address and no lifetime, so `expired_before_last_activity` stays
            // false and no lapse is claimed from a grant nobody observed.
            METHOD_CHANNEL_BIND => {
                let bound = self
                    .transactions
                    .get(&msg.transaction_id)
                    .and_then(|tx| tx.channel_number.map(|c| (c, tx.peer_address)));
                if let Some((channel, peer)) = bound {
                    self.upsert_allocation(client, server, timestamp, |alloc| {
                        let entry = alloc.channel_entry(channel, timestamp);
                        if let Some(entry) = entry {
                            entry.bound = true;
                            if peer.is_some() {
                                entry.peer = peer;
                            }
                        }
                    });
                }
            }
            _ => {}
        }
    }

    /// Attribute one relayed frame to the channel, and the allocation, that
    /// carried it.
    ///
    /// Never CREATES an allocation, for the same reason
    /// [`Self::touch_allocation`] does not: an allocation exists because an
    /// Allocate succeeded, and inventing one from a relayed frame would put a
    /// lifetime on something no server ever granted. A capture that starts
    /// after the Allocate therefore records the frames as counters and
    /// attributes them to nothing, which is the honest reading of it.
    fn record_relayed_frame(
        &mut self,
        a: SocketAddr,
        b: SocketAddr,
        channel: u16,
        bytes: u64,
        ssrc: Option<u32>,
        timestamp: chrono::DateTime<chrono::Utc>,
    ) {
        if self.allocations.is_empty() {
            return;
        }
        let key = if self.allocations.contains_key(&(a, b)) {
            (a, b)
        } else {
            (b, a)
        };
        let Some(alloc) = self.allocations.get_mut(&key) else {
            return;
        };
        let Some(entry) = alloc.channel_entry(channel, timestamp) else {
            alloc.unattributed_frames += 1;
            return;
        };
        entry.frames += 1;
        entry.bytes += bytes;
        entry.last_seen = entry.last_seen.max(timestamp);
        if let Some(ssrc) = ssrc
            && !entry.ssrcs.contains(&ssrc)
        {
            if entry.ssrcs.len() >= MAX_SSRCS_PER_CHANNEL {
                entry.ssrcs_dropped += 1;
            } else {
                entry.ssrcs.push(ssrc);
            }
        }
    }

    /// Create or update the allocation for a client/server pair.
    fn upsert_allocation(
        &mut self,
        client: SocketAddr,
        server: SocketAddr,
        timestamp: chrono::DateTime<chrono::Utc>,
        update: impl FnOnce(&mut TurnAllocation),
    ) {
        let key = (client, server);
        if !self.allocations.contains_key(&key) {
            if self.allocations.len() >= MAX_ALLOCATIONS {
                self.allocations.shift_remove_index(0);
                self.allocations_dropped += 1;
            }
            self.allocations.insert(
                key,
                TurnAllocation {
                    client,
                    server,
                    relayed_address: None,
                    lifetime_secs: None,
                    allocated_at: timestamp,
                    refreshed_at: None,
                    refreshes: 0,
                    last_activity: timestamp,
                    released: false,
                    channels: Vec::new(),
                    unattributed_frames: 0,
                },
            );
            // Release, paired with the Acquire in `note_channel_data`: the
            // insertion must be visible to any thread that observes the flag.
            ALLOCATION_SEEN.store(true, std::sync::atomic::Ordering::Release);
        }
        if let Some(alloc) = self.allocations.get_mut(&key) {
            alloc.last_activity = alloc.last_activity.max(timestamp);
            update(alloc);
        }
    }

    /// Advance an allocation's activity clock when traffic is seen on its
    /// socket pair, in either direction.
    ///
    /// Never CREATES an allocation: an allocation exists because an Allocate
    /// succeeded, and inventing one from a stray packet would put a lifetime
    /// on something that was never granted.
    fn touch_allocation(
        &mut self,
        a: SocketAddr,
        b: SocketAddr,
        timestamp: chrono::DateTime<chrono::Utc>,
    ) {
        if self.allocations.is_empty() {
            return;
        }
        // Written as two lookups rather than an `or_else` chain: the closure
        // form needs a second unique borrow of the map while the first is
        // still live, which the borrow checker refuses.
        let key = if self.allocations.contains_key(&(a, b)) {
            (a, b)
        } else {
            (b, a)
        };
        if let Some(alloc) = self.allocations.get_mut(&key) {
            alloc.last_activity = alloc.last_activity.max(timestamp);
        }
    }
}

/// Hex-encode a transaction ID for display and JSON.
fn hex_transaction_id(bytes: &[u8; 12]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(24);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// Everything the STUN and TURN tracking saw during this run.
///
/// A snapshot rather than a live view: every surface that reports it does so
/// once, at the end, and handing out a borrow of the process-global table
/// would mean holding its lock across a whole report.
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize)]
pub struct StunReport {
    /// Every tracked transaction, oldest first.
    pub transactions: Vec<StunTransaction>,
    /// Every tracked TURN allocation, oldest first.
    pub allocations: Vec<TurnAllocation>,
    /// STUN messages classified, retransmissions and evicted transactions
    /// included. Stays exact where `transactions` does not.
    pub packets: u64,
    /// Transactions evicted at the retention cap. Non-zero means
    /// `transactions` is a sample, not the whole capture.
    pub dropped: u64,
    /// Allocations evicted at the retention cap.
    pub allocations_dropped: u64,
    /// Indications seen. Counted, never tracked as transactions.
    pub indications: u64,
    /// Relayed ChannelData frames seen on a tracked allocation.
    pub channel_data_frames: u64,
    /// Relayed application bytes across those frames, framing excluded.
    pub channel_data_bytes: u64,
}

impl StunReport {
    /// Transactions that never drew a response AND whose silence is a fault.
    ///
    /// A retransmitted request that was eventually answered is NOT here — it
    /// succeeded, however slowly; [`StunTransaction::was_retransmitted`] is
    /// the weaker signal for that.
    pub fn unanswered(&self) -> impl Iterator<Item = &StunTransaction> {
        self.transactions
            .iter()
            .filter(|t| t.is_unanswered() && t.silence_is_a_fault())
    }

    /// Allocations that were still carrying traffic after the last lifetime
    /// they were granted had run out.
    pub fn lapsed_allocations(&self) -> impl Iterator<Item = &TurnAllocation> {
        self.allocations
            .iter()
            .filter(|a| a.expired_before_last_activity())
    }

    /// How many media streams were observed crossing an allocation that had
    /// already lapsed.
    ///
    /// The number the lapsed-allocation finding was missing: "one allocation
    /// lapsed" says a relay was torn down, and this says how much audio was on
    /// it when that happened. Zero is a real and different answer — the
    /// allocation lapsed with no media on it, which nobody needs woken for.
    pub fn lapsed_relayed_streams(&self) -> u64 {
        self.lapsed_allocations()
            .map(|a| a.relayed_ssrcs().len() as u64)
            .sum()
    }

    /// Whether the run saw no STUN and no TURN at all.
    pub fn is_empty(&self) -> bool {
        self.packets == 0 && self.channel_data_frames == 0
    }

    /// What ICE did in this capture: how many connectivity checks were sent,
    /// how many were answered, which pairs were nominated, and whether the
    /// two agents ever disagreed about who was in charge.
    ///
    /// Derived from the transaction table rather than stored beside it, the
    /// same way [`Self::unanswered`] and [`Self::lapsed_allocations`] are: the
    /// facts are already in the table, and a second copy of them could only
    /// ever drift from it.
    pub fn ice_summary(&self) -> IceSummary {
        let mut summary = IceSummary::default();
        // Roles each host claimed, per unordered host pair. Sets rather than a
        // single value on purpose: RFC 8445 §7.3.1.1 has the losing agent
        // SWITCH roles after a 487, so an agent that resolved a conflict
        // claimed both over the capture's life. Intersecting the sets finds
        // the conflict either way — before it was resolved and after — where
        // comparing last-seen roles would silently miss the resolved case,
        // which is the one most captures actually hold.
        let mut claimed: indexmap::IndexMap<(SocketAddr, SocketAddr), [Vec<IceRole>; 2]> =
            indexmap::IndexMap::new();
        let mut conflict_responses: indexmap::IndexMap<(SocketAddr, SocketAddr), u32> =
            indexmap::IndexMap::new();
        // Every pair a nomination was seen on, not only the ones that fit in
        // `nominated` — a conflict on the hundredth nominated pair is still a
        // conflict ICE resolved, and reading `resolved` off the capped list
        // would call it unresolved because the report ran out of rows.
        // Bounded by the transaction table it is derived from.
        let mut nominated_pairs: indexmap::IndexSet<(SocketAddr, SocketAddr)> =
            indexmap::IndexSet::new();

        for tx in &self.transactions {
            if !tx.is_ice_check() {
                continue;
            }
            summary.checks += 1;
            if tx.responded_at.is_some() {
                summary.checks_answered += 1;
            }
            if tx.nominated_pair() {
                summary.nominated_total += 1;
                nominated_pairs.insert(pair_key(tx.client, tx.server).0);
                if summary.nominated.len() < MAX_ICE_ROWS {
                    summary.nominated.push(NominatedPair {
                        local: tx.client,
                        remote: tx.server,
                        role: tx.ice_role,
                        priority: tx.priority,
                        nominated_at: tx.responded_at.unwrap_or(tx.last_request),
                        rtt_ms: tx.rtt_ms,
                    });
                }
            }
            let (key, side) = pair_key(tx.client, tx.server);
            if let Some(role) = tx.ice_role {
                let entry = claimed.entry(key).or_default();
                if !entry[side].contains(&role) {
                    entry[side].push(role);
                }
            }
            // 487 Role Conflict, the answer an agent gives when the peer
            // claimed the role it holds itself (RFC 8445 §7.3.1.1). Counted
            // on the pair rather than raised on its own, because it and the
            // duplicate-role claim are the same fault seen from the two ends.
            if tx.error_code == Some(487) {
                *conflict_responses.entry(key).or_default() += 1;
            }
        }

        let mut pairs: Vec<(SocketAddr, SocketAddr)> = claimed.keys().copied().collect();
        for key in conflict_responses.keys() {
            if !pairs.contains(key) {
                pairs.push(*key);
            }
        }
        for key in pairs {
            let roles = claimed.get(&key);
            let both: Vec<IceRole> = roles
                .map(|r| {
                    r[0].iter()
                        .filter(|role| r[1].contains(role))
                        .copied()
                        .collect()
                })
                .unwrap_or_default();
            let responses = conflict_responses.get(&key).copied().unwrap_or(0);
            if both.is_empty() && responses == 0 {
                continue;
            }
            summary.role_conflicts_total += 1;
            if summary.role_conflicts.len() < MAX_ICE_ROWS {
                summary.role_conflicts.push(IceRoleConflict {
                    a: key.0,
                    b: key.1,
                    role: both.first().copied(),
                    role_conflict_responses: responses,
                    // Whether ICE got past it. A conflict the agents resolved
                    // cost a round trip and nothing else, and reporting it at
                    // the same weight as one that never resolved would train
                    // a reader to skip both.
                    resolved: nominated_pairs.contains(&key),
                });
            }
        }
        summary
    }
}

/// Rows retained for each ICE list (D17). Both lists are already bounded by
/// the transaction table they are derived from; this bounds what a REPORT
/// carries, so a capture full of ICE cannot turn one finding into ten thousand
/// lines. The `_total` counters beside them stay exact.
pub const MAX_ICE_ROWS: usize = 64;

/// An unordered key for a host pair, plus which side of it `a` is.
///
/// Sorted so the same pair keys identically whichever direction the packet
/// went, which is what lets a check and the peer's mirror image of it land in
/// one entry instead of two — and two entries is exactly how one
/// misconfiguration would be reported twice.
fn pair_key(a: SocketAddr, b: SocketAddr) -> ((SocketAddr, SocketAddr), usize) {
    if a <= b { ((a, b), 0) } else { ((b, a), 1) }
}

/// A candidate pair an ICE agent nominated, and the peer confirmed.
///
/// The ICE answer to the question `XOR-MAPPED-ADDRESS` answers for plain STUN:
/// which path the media actually took. Without it a capture of an ICE exchange
/// that converged and one that never did read the same — a pile of Binding
/// Requests on a media port, with nothing saying which of them won.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct NominatedPair {
    /// The socket the nominating check left from.
    pub local: SocketAddr,
    /// The socket it was sent to. Together with `local` this is the pair, and
    /// it is the 5-tuple a follow-up capture filter has to match.
    pub remote: SocketAddr,
    /// The role the nominating agent claimed. Only a controlling agent may
    /// nominate (RFC 8445 §8.1.1), so anything else here is worth seeing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<IceRole>,
    /// The `PRIORITY` the check carried, reported and never recomputed —
    /// sipnab is an observer, not an ICE agent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<u32>,
    /// When the peer confirmed it.
    pub nominated_at: chrono::DateTime<chrono::Utc>,
    /// Round-trip time of the nominating exchange, in milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rtt_ms: Option<f64>,
}

/// Two ICE agents that disagreed about which of them was in charge.
///
/// A real misconfiguration, and one whose only other symptom is media that
/// takes a long time to start or never starts at all: RFC 8445 §7.3.1.1 has
/// the agent that detects it answer `487 Role Conflict`, and one side then
/// switches role and repeats every check it had already sent.
///
/// Both shapes of evidence are folded into one record because they are the
/// same fault seen from the two ends — the duplicate claim is what the
/// requests show, and the `487` is what the answer to them shows. Two records
/// would report one misconfiguration twice.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct IceRoleConflict {
    /// One endpoint of the pair.
    pub a: SocketAddr,
    /// The other. Ordered so the same pair renders identically whichever
    /// direction the first packet went.
    pub b: SocketAddr,
    /// The role both sides claimed, when the conflict was seen that way.
    ///
    /// `None` where the only evidence is a `487` — the request that provoked
    /// it may not be in the capture, and naming a role nobody was observed to
    /// claim would be an invention.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<IceRole>,
    /// How many `487 Role Conflict` responses were seen on this pair.
    pub role_conflict_responses: u32,
    /// Whether a candidate pair between these two was nominated anyway.
    ///
    /// `true` means ICE resolved the conflict itself and the call went on —
    /// it cost a round trip. `false` means nothing was ever nominated between
    /// them, and the conflict is a candidate cause of media that never
    /// started.
    pub resolved: bool,
}

/// What ICE achieved in this capture.
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize)]
pub struct IceSummary {
    /// Connectivity checks seen — Binding Requests carrying the ICE
    /// attributes RFC 8445 §7.2.1 requires, which is what tells them from a
    /// plain server-reflexive probe to a STUN server.
    pub checks: u64,
    /// How many of those drew an answer of either kind.
    ///
    /// Reported as a COUNT and deliberately not as a finding of its own. An
    /// endpoint whose checks all went unanswered is a real and serious
    /// condition — ICE never completed and the call has no media path — but
    /// every one of those transactions is ALREADY reported, individually, by
    /// [`StunReport::unanswered`] and by the `unanswered_stun_probe` finding.
    /// A second finding over the same rows would report one silence twice and
    /// make a capture look like it had two problems. `checks_answered == 0`
    /// with `checks > 0` is the reading, and it is one subtraction away.
    pub checks_answered: u64,
    /// Nominated pairs, capped at [`MAX_ICE_ROWS`].
    pub nominated: Vec<NominatedPair>,
    /// Nominations seen, exact past the cap.
    pub nominated_total: u64,
    /// Role conflicts, capped at [`MAX_ICE_ROWS`].
    pub role_conflicts: Vec<IceRoleConflict>,
    /// Role conflicts seen, exact past the cap.
    pub role_conflicts_total: u64,
}

impl IceSummary {
    /// Whether this capture holds any ICE at all.
    pub fn is_empty(&self) -> bool {
        self.checks == 0 && self.nominated_total == 0 && self.role_conflicts_total == 0
    }

    /// Nominations the cap kept out of [`Self::nominated`].
    pub fn nominated_dropped(&self) -> u64 {
        self.nominated_total
            .saturating_sub(self.nominated.len() as u64)
    }

    /// Role conflicts the cap kept out of [`Self::role_conflicts`].
    pub fn role_conflicts_dropped(&self) -> u64 {
        self.role_conflicts_total
            .saturating_sub(self.role_conflicts.len() as u64)
    }
}

/// Every transaction whose CLIENT socket carries this address, cloned.
///
/// The targeted read [`crate::rtp::diagnosis`] needs, and the reason it is not
/// a filter over [`report`]: that call clones the whole table, and the media
/// diagnosis asks this question once per dialog that advertised an unroutable
/// address — which on a LAN-only capture is every dialog it has. Cloning ten
/// thousand transactions per call would make the finding quadratic in the size
/// of the capture. This locks once and clones only what matched, which on a
/// healthy dialog is nothing.
///
/// Answered from a relaxed atomic, with no lock taken at all, when the run has
/// seen no STUN.
pub fn transactions_from(client_ip: IpAddr) -> Vec<StunTransaction> {
    if !STUN_SEEN.load(std::sync::atomic::Ordering::Acquire) {
        return Vec::new();
    }
    let Ok(guard) = TRACKER.lock() else {
        return Vec::new();
    };
    let Some(tracker) = guard.as_ref() else {
        return Vec::new();
    };
    tracker
        .transactions
        .values()
        .filter(|t| t.client.ip() == client_ip)
        .cloned()
        .collect()
}

/// Everything STUN and TURN said during this run.
pub fn report() -> StunReport {
    let Ok(guard) = TRACKER.lock() else {
        return StunReport::default();
    };
    let Some(tracker) = guard.as_ref() else {
        return StunReport::default();
    };
    StunReport {
        transactions: tracker.transactions.values().cloned().collect(),
        allocations: tracker.allocations.values().cloned().collect(),
        packets: tracker.packets,
        dropped: tracker.dropped,
        allocations_dropped: tracker.allocations_dropped,
        indications: tracker.indications,
        channel_data_frames: tracker.channel_data_frames,
        channel_data_bytes: tracker.channel_data_bytes,
    }
}

/// How many answers were authentication challenges.
pub fn auth_challenges() -> u64 {
    let Ok(guard) = TRACKER.lock() else {
        return 0;
    };
    guard.as_ref().map_or(0, |t| {
        t.transactions.values().filter(|x| x.auth_challenge).count() as u64
    })
}

/// Binding and Allocate requests that never got an answer, busiest first, with
/// the number that DID get one for scale.
pub fn unanswered_requests() -> (Vec<UnansweredRequest>, u64) {
    let Ok(guard) = TRACKER.lock() else {
        return (Vec::new(), 0);
    };
    let Some(tracker) = guard.as_ref() else {
        return (Vec::new(), 0);
    };
    let mut out: Vec<UnansweredRequest> = Vec::new();
    let mut answered = 0u64;
    for tx in tracker.transactions.values() {
        if !tx.silence_is_a_fault() {
            continue;
        }
        // A transaction filed from a response alone had its request before the
        // capture began. It is not evidence that anything worked HERE, so it
        // is left out of the denominator rather than inflating it.
        if tx.request_count == 0 {
            continue;
        }
        if tx.is_unanswered() {
            out.push(UnansweredRequest {
                from: tx.client,
                to: tx.server,
                attempts: tx.request_count,
                software: tx.software.clone(),
                method: tx.method_name.clone(),
            });
        } else {
            answered += 1;
        }
    }
    // Most-retried first, then by address so two runs over one capture print
    // the same order.
    out.sort_by(|a, b| {
        b.attempts
            .cmp(&a.attempts)
            .then_with(|| a.from.to_string().cmp(&b.from.to_string()))
    });
    (out, answered)
}

/// Clear the tracker, for a process that analyzes several captures in sequence
/// and for tests that assert on exact counts.
pub fn reset() {
    if let Ok(mut guard) = TRACKER.lock() {
        *guard = None;
    }
    STUN_SEEN.store(false, std::sync::atomic::Ordering::Release);
    ALLOCATION_SEEN.store(false, std::sync::atomic::Ordering::Release);
}

#[cfg(test)]
mod turn_tests {
    use super::*;

    /// A fixed capture timestamp `ms` milliseconds into an imaginary capture,
    /// so the timing assertions do not depend on when the test ran.
    pub(super) fn ts(ms: i64) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::from_timestamp_millis(1_700_000_000_000 + ms).expect("valid timestamp")
    }

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
    fn channel_data_is_recognized_and_never_confused_with_stun_or_rtp() {
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
    #[serial_test::serial(stun_store)]
    fn an_answered_request_is_struck_off_and_an_unanswered_one_stands() {
        reset();
        let src: SocketAddr = "192.0.2.10:5060".parse().unwrap();
        let dst: SocketAddr = "198.51.100.1:3478".parse().unwrap();

        let asked = parse(&message(0x0001, [0xAA; 12], &[])).unwrap();
        let ignored = parse(&message(0x0001, [0xBB; 12], &[])).unwrap();
        note_message(&asked, src, dst, ts(0));
        note_message(&ignored, src, dst, ts(0));
        // The ignored one is retransmitted: one question, two attempts.
        note_message(&ignored, src, dst, ts(500));

        let answer = parse(&message(0x0101, [0xAA; 12], &[])).unwrap();
        note_message(&answer, dst, src, ts(30));

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
    #[serial_test::serial(stun_store)]
    fn an_error_response_counts_as_answered() {
        reset();
        let src: SocketAddr = "192.0.2.10:5060".parse().unwrap();
        let dst: SocketAddr = "198.51.100.1:3478".parse().unwrap();
        let asked = parse(&message(0x0001, [0xCC; 12], &[])).unwrap();
        note_message(&asked, src, dst, ts(0));
        let refused = parse(&message(
            0x0111,
            [0xCC; 12],
            &[(0x0009, vec![0, 0, 0x04, 0x01])],
        ))
        .unwrap();
        assert_eq!(refused.error_code, Some(401));
        note_message(&refused, dst, src, ts(10));

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

#[cfg(test)]
mod turn_allocation_attribute_tests {
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
        m.extend_from_slice(&[0x6b; 12]);
        m.extend_from_slice(&body);
        m
    }

    /// The four attributes an Allocate request uses to SHAPE the allocation.
    /// Without them a request for an IPv6 relay and one for an IPv4 relay are
    /// the same row, and a `440` refusal has no visible cause.
    #[test]
    fn an_allocate_request_reports_the_shape_it_asked_for() {
        let m = msg(
            0x0003, // Allocate request
            &[
                (0x0019, vec![17, 0, 0, 0]),   // REQUESTED-TRANSPORT UDP
                (0x0017, vec![0x02, 0, 0, 0]), // REQUESTED-ADDRESS-FAMILY IPv6
                (0x0018, vec![0x80]),          // EVEN-PORT, R bit set
                (0x001a, Vec::new()),          // DONT-FRAGMENT
            ],
        );
        let parsed = parse(&m).expect("parses");
        assert_eq!(parsed.requested_transport, Some(17));
        assert_eq!(parsed.requested_address_family, Some(0x02), "IPv6");
        assert_eq!(
            parsed.even_port,
            Some(true),
            "the R bit is the ask that reserves the RTCP port beside the RTP one"
        );
        assert!(parsed.dont_fragment);
    }

    /// EVEN-PORT without the R bit is a DIFFERENT ask, and absent is a third
    /// state. Collapsing any two of the three would misreport the request.
    #[test]
    fn even_port_distinguishes_asked_asked_with_reservation_and_absent() {
        let with_r = parse(&msg(0x0003, &[(0x0018, vec![0x80])])).expect("parses");
        assert_eq!(with_r.even_port, Some(true));
        let without_r = parse(&msg(0x0003, &[(0x0018, vec![0x00])])).expect("parses");
        assert_eq!(without_r.even_port, Some(false));
        let absent = parse(&msg(0x0003, &[])).expect("parses");
        assert_eq!(
            absent.even_port, None,
            "absent is not the same as not asked"
        );
    }

    /// RESERVATION-TOKEN is what claims the port an earlier EVEN-PORT
    /// reserved, so a capture where the second Allocate carries no token
    /// explains why the pair was not honored.
    #[test]
    fn a_reservation_token_survives_as_all_sixty_four_bits() {
        let token: u64 = 0x0123_4567_89ab_cdef;
        let m = msg(0x0003, &[(0x0022, token.to_be_bytes().to_vec())]);
        assert_eq!(parse(&m).expect("parses").reservation_token, Some(token));
        // A short token is refused rather than padded: half a token is not a
        // token, and reporting one would name a reservation nobody made.
        let short = msg(0x0003, &[(0x0022, vec![0x01, 0x23, 0x45, 0x67])]);
        assert_eq!(parse(&short).expect("parses").reservation_token, None);
    }

    /// DATA locates the relayed payload inside the message rather than copying
    /// it, so a caller can re-slice its own buffer.
    #[test]
    fn a_data_attribute_locates_the_relayed_payload() {
        let payload: Vec<u8> = (0u8..16).collect();
        let m = msg(0x0016, &[(0x0013, payload.clone())]); // Send indication
        let parsed = parse(&m).expect("parses");
        let range = parsed.data.expect("DATA must be located");
        assert_eq!(
            &m[range],
            &payload[..],
            "the range must name the relayed bytes exactly"
        );
        // An empty DATA relays nothing and must not produce a zero-length
        // range for a caller to slice with.
        let empty = msg(0x0016, &[(0x0013, Vec::new())]);
        assert_eq!(parse(&empty).expect("parses").data, None);
    }

    /// A truncated LIFETIME must be REFUSED, never zero-extended. Reading two
    /// bytes as a u32 invents a short expiry the sender never claimed — and
    /// `expired_before_last_activity` draws a conclusion from exactly that
    /// number, so a fabricated one produces a fabricated finding.
    #[test]
    fn a_truncated_lifetime_is_refused_rather_than_zero_extended() {
        let full = msg(0x0103, &[(0x000D, 600u32.to_be_bytes().to_vec())]);
        assert_eq!(parse(&full).expect("parses").lifetime, Some(600));
        for short in [vec![0x02u8], vec![0x02, 0x58], vec![0x00, 0x02, 0x58]] {
            let m = msg(0x0103, &[(0x000D, short.clone())]);
            assert_eq!(
                parse(&m).expect("parses").lifetime,
                None,
                "a {}-byte LIFETIME must not become a number",
                short.len()
            );
        }
    }
}

#[cfg(test)]
mod channel_framing_tests {
    use super::*;

    /// The tightened rule. A stray datagram whose first two bytes land in the
    /// channel-number window and whose length field describes only part of it
    /// is NOT a relay frame — and the old floor (`len >= 4 + declared`)
    /// accepted it, then let the pipeline re-classify whatever followed. That
    /// is the phantom-stream class arrived at from the other side.
    #[test]
    fn a_datagram_the_frame_does_not_account_for_is_not_channel_data() {
        let mut stray = vec![0x40, 0x01, 0x00, 0x08];
        stray.extend_from_slice(&[0xaa; 8]);
        assert!(is_channel_data(&stray), "the exact frame is one");
        stray.extend_from_slice(&[0xbb; 9]); // nine trailing bytes, unaccounted
        assert!(
            !is_channel_data(&stray),
            "over UDP the frame must account for the whole datagram"
        );
        assert!(channel_data_payload(&stray).is_none());
    }

    /// The optional padding RFC 5766 §11.5 allows over a datagram transport
    /// must still be accepted, or a conformant sender's media disappears.
    #[test]
    fn the_optional_datagram_padding_is_accepted() {
        let mut unpadded = vec![0x40, 0x02, 0x00, 0x0d];
        unpadded.extend_from_slice(&[0xaa; 13]);
        assert!(is_channel_data(&unpadded));
        let mut padded = unpadded.clone();
        padded.extend_from_slice(&[0x00; 3]);
        assert!(is_channel_data(&padded));
        assert_eq!(
            channel_data_payload(&padded).expect("unwraps").len(),
            13,
            "the padding is framing, not payload"
        );
    }

    /// On a byte stream the padding is mandatory and the next frame may
    /// follow, so the rule is "the padded frame fits" rather than "the frame
    /// is the whole buffer".
    #[test]
    fn stream_framing_allows_a_following_frame() {
        let mut data = vec![0x40, 0x03, 0x00, 0x0d];
        data.extend_from_slice(&[0xaa; 13]);
        data.extend_from_slice(&[0x00; 3]); // padding
        data.extend_from_slice(&[0xbb; 8]); // the next frame
        assert!(is_channel_data_framed(&data, ChannelDataFraming::Stream));
        assert!(
            !is_channel_data_framed(&data, ChannelDataFraming::Datagram),
            "the datagram rule refuses a frame that leaves bytes over"
        );
        assert_eq!(
            channel_data_payload_framed(&data, ChannelDataFraming::Stream)
                .expect("unwraps")
                .len(),
            13
        );
    }

    /// A zero-length frame carries nothing, and accepting it would let ANY
    /// four-byte datagram starting in the window be claimed as relayed media —
    /// the one shape where every other check passes for free.
    #[test]
    fn a_zero_length_frame_is_refused() {
        assert!(!is_channel_data(&[0x40, 0x01, 0x00, 0x00]));
        assert!(!is_channel_data_framed(
            &[0x40, 0x01, 0x00, 0x00],
            ChannelDataFraming::Stream
        ));
    }

    /// No input of any length may panic: this runs on the first four bytes of
    /// arbitrary UDP.
    #[test]
    fn arbitrary_input_never_panics() {
        let mut seed: u32 = 0x1234_5678;
        for len in 0..64usize {
            let mut buf = vec![0u8; len];
            for b in buf.iter_mut() {
                seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                *b = (seed >> 24) as u8;
            }
            let _ = is_channel_data(&buf);
            let _ = is_channel_data_framed(&buf, ChannelDataFraming::Stream);
            let _ = channel_data_payload(&buf);
        }
    }
}

#[cfg(test)]
mod allocation_tracking_tests {
    use super::turn_tests::ts;
    use super::*;

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

    fn client() -> SocketAddr {
        "192.0.2.10:50000".parse().expect("valid addr")
    }

    /// A ChannelData frame on `channel` wrapping a 172-byte RTP packet whose
    /// SSRC is `ssrc`: the exact shape a relayed talk spurt has on the wire.
    ///
    /// Assembled from literal bytes rather than from anything in this module,
    /// so a frame that this module would mis-frame cannot be built by the same
    /// mistake that reads it.
    pub(super) fn relayed_rtp(channel: u16, ssrc: u32) -> Vec<u8> {
        let mut frame = Vec::with_capacity(176);
        frame.extend_from_slice(&channel.to_be_bytes());
        frame.extend_from_slice(&172u16.to_be_bytes());
        frame.push(0x80); // version 2, no padding, no extension, CSRC count 0
        frame.push(0x00); // payload type 0 (PCMU), marker clear
        frame.extend_from_slice(&1u16.to_be_bytes()); // sequence
        frame.extend_from_slice(&160u32.to_be_bytes()); // RTP timestamp
        frame.extend_from_slice(&ssrc.to_be_bytes());
        frame.extend(std::iter::repeat_n(0xd5u8, 160));
        frame
    }
    fn server() -> SocketAddr {
        "198.51.100.20:3478".parse().expect("valid addr")
    }

    /// Grant an allocation with `lifetime` seconds at t=0.
    fn allocate(lifetime: u32) {
        let req = parse(&message(0x0003, [0x11; 12], &[])).expect("parses");
        note_message(&req, client(), server(), ts(0));
        let resp = parse(&message(
            0x0103,
            [0x11; 12],
            &[
                (0x0016, xor_v4([198, 51, 100, 77], 49160)),
                (0x000D, lifetime.to_be_bytes().to_vec()),
            ],
        ))
        .expect("parses");
        note_message(&resp, server(), client(), ts(10));
    }

    /// The finding: traffic still crossing the relay after the last granted
    /// lifetime could have sustained it, with no Refresh in between. The
    /// operational shape of a call that dies partway through with no SIP
    /// message anywhere to explain it.
    #[test]
    #[serial_test::serial(stun_store)]
    fn an_allocation_still_carrying_traffic_past_its_lifetime_is_lapsed() {
        reset();
        allocate(60);
        // Relayed media a minute and a half in, long after the 60s grant.
        note_channel_data(
            client(),
            server(),
            &relayed_rtp(0x4001, 0x1122_3344),
            ts(90_000),
        );

        let report = report();
        assert_eq!(report.allocations.len(), 1);
        let lapsed: Vec<_> = report.lapsed_allocations().collect();
        assert_eq!(lapsed.len(), 1, "the relay was torn down under the media");
        assert_eq!(
            lapsed[0].relayed_address.map(|a| a.to_string()).as_deref(),
            Some("198.51.100.77:49160")
        );
        // 29 rather than 30: the grant is timed from the response at t=10ms,
        // so the expiry lands at 60.010s and 90s is 29.99s past it.
        assert_eq!(lapsed[0].seconds_past_expiry(), Some(29));
        assert_eq!(report.channel_data_frames, 1);
        reset();
    }

    /// A Refresh that arrives in time moves the expiry, so the same traffic is
    /// no longer past it. Without this the finding would fire on every healthy
    /// long call.
    #[test]
    #[serial_test::serial(stun_store)]
    fn a_refresh_that_kept_up_is_not_a_lapse() {
        reset();
        allocate(60);
        let req = parse(&message(0x0004, [0x22; 12], &[])).expect("parses");
        note_message(&req, client(), server(), ts(50_000));
        let resp = parse(&message(
            0x0104,
            [0x22; 12],
            &[(0x000D, 600u32.to_be_bytes().to_vec())],
        ))
        .expect("parses");
        note_message(&resp, server(), client(), ts(50_010));
        note_channel_data(
            client(),
            server(),
            &relayed_rtp(0x4001, 0x1122_3344),
            ts(90_000),
        );

        assert_eq!(report().lapsed_allocations().count(), 0);
        assert_eq!(report().allocations[0].refreshes, 1);
        reset();
    }

    /// A Refresh with `LIFETIME` 0 is a deliberate RELEASE (RFC 5766 §7). The
    /// client asked for the teardown, so the teardown is not a fault — and a
    /// stray packet arriving afterwards must not turn it into one.
    #[test]
    #[serial_test::serial(stun_store)]
    fn a_released_allocation_is_never_reported_as_lapsed() {
        reset();
        allocate(60);
        let req = parse(&message(0x0004, [0x33; 12], &[])).expect("parses");
        note_message(&req, client(), server(), ts(20_000));
        let resp = parse(&message(
            0x0104,
            [0x33; 12],
            &[(0x000D, 0u32.to_be_bytes().to_vec())],
        ))
        .expect("parses");
        note_message(&resp, server(), client(), ts(20_010));
        note_channel_data(
            client(),
            server(),
            &relayed_rtp(0x4001, 0x1122_3344),
            ts(90_000),
        );

        assert!(report().allocations[0].released);
        assert_eq!(
            report().lapsed_allocations().count(),
            0,
            "a release the client asked for is not a relay that lapsed under it"
        );
        reset();
    }

    /// Relayed media must never CREATE an allocation. Inventing one from a
    /// stray frame would put a lifetime on something no server ever granted.
    #[test]
    #[serial_test::serial(stun_store)]
    fn relayed_media_without_an_allocation_records_nothing() {
        reset();
        note_channel_data(
            client(),
            server(),
            &relayed_rtp(0x4001, 0x1122_3344),
            ts(1_000),
        );
        let report = report();
        assert!(report.allocations.is_empty());
        assert_eq!(
            report.channel_data_frames, 0,
            "the relaxed-atomic fast path must skip the store entirely"
        );
        reset();
    }

    /// The transaction table keeps ANSWERED transactions too, which is what
    /// lets a report say "1 of 3" rather than listing one failure with no
    /// scale — and what lets the SDP diagnosis find the address a client was
    /// handed and did not use.
    #[test]
    #[serial_test::serial(stun_store)]
    fn answered_transactions_stay_in_the_table_with_their_addresses() {
        reset();
        let req = parse(&message(0x0001, [0x44; 12], &[])).expect("parses");
        note_message(&req, client(), server(), ts(0));
        let resp = parse(&message(
            0x0101,
            [0x44; 12],
            &[(0x0020, xor_v4([203, 0, 113, 5], 12262))],
        ))
        .expect("parses");
        note_message(&resp, server(), client(), ts(7));

        let report = report();
        assert_eq!(report.transactions.len(), 1);
        let tx = &report.transactions[0];
        assert_eq!(
            tx.mapped_address.map(|a| a.to_string()).as_deref(),
            Some("203.0.113.5:12262")
        );
        assert_eq!(tx.rtt_ms, Some(7.0));
        assert!(!tx.is_unanswered());
        assert_eq!(report.unanswered().count(), 0);
        reset();
    }

    /// A CreatePermission that goes unanswered is NOT reported as a failed
    /// probe. It rides an allocation that already succeeded, so its silence is
    /// a consequence, and listing it would bury the request that actually
    /// failed under the ones that followed it.
    #[test]
    #[serial_test::serial(stun_store)]
    fn only_binding_and_allocate_silence_counts_as_a_fault() {
        reset();
        let perm = parse(&message(0x0008, [0x55; 12], &[])).expect("parses");
        note_message(&perm, client(), server(), ts(0));
        let bind = parse(&message(0x0001, [0x66; 12], &[])).expect("parses");
        note_message(&bind, client(), server(), ts(1));

        let report = report();
        assert_eq!(report.transactions.len(), 2, "both are tracked");
        assert_eq!(
            report.unanswered().count(),
            1,
            "only the Binding's silence is a fault"
        );
        let (unanswered, _) = unanswered_requests();
        assert_eq!(unanswered.len(), 1);
        assert_eq!(unanswered[0].method, "Binding");
        reset();
    }
}

#[cfg(test)]
mod ice_state_tests {
    use super::turn_tests::ts;
    use super::*;

    /// One agent, one peer, one check. Attributes are written out as literal
    /// bytes rather than assembled by anything in this module, so a parser
    /// that reads them wrongly cannot agree with a builder that writes them
    /// the same wrong way.
    fn check(
        txn: u8,
        priority: Option<u32>,
        role: Option<IceRole>,
        use_candidate: bool,
    ) -> Vec<u8> {
        let mut body: Vec<u8> = Vec::new();
        if let Some(p) = priority {
            body.extend_from_slice(&[0x00, 0x24, 0x00, 0x04]); // PRIORITY, 4 bytes
            body.extend_from_slice(&p.to_be_bytes());
        }
        if let Some(role) = role {
            body.extend_from_slice(match role {
                IceRole::Controlling => &[0x80, 0x2a, 0x00, 0x08],
                IceRole::Controlled => &[0x80, 0x29, 0x00, 0x08],
            });
            // The tie-breaker, which sipnab reads past and never interprets.
            body.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        }
        if use_candidate {
            body.extend_from_slice(&[0x00, 0x25, 0x00, 0x00]); // USE-CANDIDATE, empty
        }
        let mut m: Vec<u8> = vec![0x00, 0x01]; // Binding Request
        m.extend_from_slice(&(body.len() as u16).to_be_bytes());
        m.extend_from_slice(&[0x21, 0x12, 0xa4, 0x42]); // magic cookie, literal
        m.extend_from_slice(&[txn; 12]);
        m.extend_from_slice(&body);
        m
    }

    /// A Binding SUCCESS response carrying XOR-MAPPED-ADDRESS 192.0.2.10:50004,
    /// written out as the bytes that appear on the wire.
    fn success(txn: u8) -> Vec<u8> {
        vec![
            0x01, 0x01, 0x00, 0x0c, // Binding success, 12 bytes of attributes
            0x21, 0x12, 0xa4, 0x42, // magic cookie
            txn, txn, txn, txn, txn, txn, txn, txn, txn, txn, txn, txn, // txn id
            0x00, 0x20, 0x00, 0x08, // XOR-MAPPED-ADDRESS, 8 bytes
            0x00, 0x01, // reserved, family IPv4
            // port 50004 ^ 0x2112 = 0xC354 ^ 0x2112; 50004 == 0xC354
            0xe2, 0x46, // 0xC354 ^ 0x2112
            // 192.0.2.10 ^ 21 12 a4 42
            0xe1, 0x12, 0xa6, 0x48,
        ]
    }

    /// A Binding ERROR response carrying `487 Role Conflict`.
    fn role_conflict_error(txn: u8) -> Vec<u8> {
        vec![
            0x01, 0x11, 0x00, 0x08, // Binding error, 8 bytes of attributes
            0x21, 0x12, 0xa4, 0x42, // magic cookie
            txn, txn, txn, txn, txn, txn, txn, txn, txn, txn, txn, txn, // txn id
            0x00, 0x09, 0x00, 0x04, // ERROR-CODE, 4 bytes
            0x00, 0x00, 0x04, 0x57, // class 4, number 87 => 487
        ]
    }

    fn agent_a() -> SocketAddr {
        "192.0.2.10:50004".parse().expect("valid addr")
    }
    fn agent_b() -> SocketAddr {
        "203.0.113.9:16000".parse().expect("valid addr")
    }

    /// The literal success bytes above must decode to the address they were
    /// written for. Without this the two tests below could both be satisfied
    /// by a decoder that produced nonsense consistently.
    #[test]
    fn the_literal_success_bytes_decode_to_the_address_they_encode() {
        let msg = parse(&success(0x11)).expect("parses");
        assert_eq!(
            msg.mapped_address.map(|a| a.to_string()).as_deref(),
            Some("192.0.2.10:50004")
        );
    }

    /// A connectivity check is a Binding Request carrying the ICE attributes
    /// RFC 8445 requires. A plain server-reflexive probe carries none of them
    /// and must never be counted as one, or every NAT probe in the capture
    /// would read as an ICE check that failed.
    #[test]
    #[serial_test::serial(stun_store)]
    fn a_server_reflexive_probe_is_not_counted_as_an_ice_check() {
        reset();
        let probe = parse(&check(0x01, None, None, false)).expect("parses");
        note_message(
            &probe,
            agent_a(),
            "198.51.100.20:3478".parse().expect("addr"),
            ts(0),
        );
        let ice = report().ice_summary();
        assert_eq!(ice.checks, 0, "a bare Binding Request is not an ICE check");
        assert!(ice.is_empty());
        reset();
    }

    /// The nomination, which is the ICE analogue of the mapped address: it
    /// names the path the media actually took.
    #[test]
    #[serial_test::serial(stun_store)]
    fn a_nominated_pair_is_reported_once_the_peer_agrees() {
        reset();
        let nominating = parse(&check(
            0x12,
            Some(2_130_706_431),
            Some(IceRole::Controlling),
            true,
        ))
        .expect("parses");
        note_message(&nominating, agent_a(), agent_b(), ts(100));
        let reply = parse(&success(0x12)).expect("parses");
        note_message(&reply, agent_b(), agent_a(), ts(118));

        let ice = report().ice_summary();
        assert_eq!(ice.checks, 1);
        assert_eq!(ice.checks_answered, 1);
        assert_eq!(ice.nominated_total, 1);
        let pair = &ice.nominated[0];
        assert_eq!(pair.local, agent_a());
        assert_eq!(pair.remote, agent_b());
        assert_eq!(pair.role, Some(IceRole::Controlling));
        assert_eq!(pair.priority, Some(2_130_706_431));
        assert_eq!(pair.rtt_ms, Some(18.0));
        reset();
    }

    /// A nomination nobody answered nominated nothing: the pair was never
    /// validated, so reporting it as the media path would name a path that
    /// carried none.
    #[test]
    #[serial_test::serial(stun_store)]
    fn an_unanswered_nomination_nominates_nothing() {
        reset();
        let nominating =
            parse(&check(0x13, Some(1), Some(IceRole::Controlling), true)).expect("parses");
        note_message(&nominating, agent_a(), agent_b(), ts(0));

        let ice = report().ice_summary();
        assert_eq!(ice.checks, 1);
        assert_eq!(ice.checks_answered, 0, "ICE never completed");
        assert_eq!(ice.nominated_total, 0);
        // And the transaction is ALSO in the unanswered list, which is where
        // the silence is reported. The ICE summary counts it and deliberately
        // does not raise a second finding over the same row.
        assert_eq!(report().unanswered().count(), 1);
        reset();
    }

    /// Two agents claiming the same role is the misconfiguration. Detected
    /// from the requests alone, with no 487 anywhere.
    #[test]
    #[serial_test::serial(stun_store)]
    fn both_agents_claiming_one_role_is_a_conflict() {
        reset();
        let from_a = parse(&check(0x21, Some(9), Some(IceRole::Controlling), false)).expect("ok");
        note_message(&from_a, agent_a(), agent_b(), ts(0));
        let from_b = parse(&check(0x22, Some(8), Some(IceRole::Controlling), false)).expect("ok");
        note_message(&from_b, agent_b(), agent_a(), ts(10));

        let ice = report().ice_summary();
        assert_eq!(ice.role_conflicts_total, 1, "one pair, not two rows");
        let conflict = &ice.role_conflicts[0];
        assert_eq!(conflict.role, Some(IceRole::Controlling));
        assert_eq!(conflict.role_conflict_responses, 0, "no 487 was sent");
        assert!(!conflict.resolved, "nothing was ever nominated");
        reset();
    }

    /// A `487 Role Conflict` response is the same fault seen from the other
    /// end, and must fold into ONE record rather than raising a second.
    #[test]
    #[serial_test::serial(stun_store)]
    fn a_487_and_a_duplicate_claim_are_one_conflict_not_two() {
        reset();
        let from_a = parse(&check(0x31, Some(9), Some(IceRole::Controlling), false)).expect("ok");
        note_message(&from_a, agent_a(), agent_b(), ts(0));
        let refusal = parse(&role_conflict_error(0x31)).expect("parses");
        note_message(&refusal, agent_b(), agent_a(), ts(12));
        let from_b = parse(&check(0x32, Some(8), Some(IceRole::Controlling), false)).expect("ok");
        note_message(&from_b, agent_b(), agent_a(), ts(20));

        let ice = report().ice_summary();
        assert_eq!(ice.role_conflicts_total, 1);
        assert_eq!(ice.role_conflicts[0].role_conflict_responses, 1);
        reset();
    }

    /// RFC 8445 §7.3.1.1 has the losing agent SWITCH roles and repeat its
    /// checks, so a resolved conflict leaves BOTH roles on record for one
    /// agent. Comparing last-seen roles would miss it entirely; the sets must
    /// still intersect, and the nomination that followed must mark it
    /// resolved rather than let it read as a call that never got media.
    #[test]
    #[serial_test::serial(stun_store)]
    fn a_conflict_ice_resolved_is_reported_as_resolved() {
        reset();
        let both_controlling_a =
            parse(&check(0x41, Some(9), Some(IceRole::Controlling), false)).expect("ok");
        note_message(&both_controlling_a, agent_a(), agent_b(), ts(0));
        let both_controlling_b =
            parse(&check(0x42, Some(8), Some(IceRole::Controlling), false)).expect("ok");
        note_message(&both_controlling_b, agent_b(), agent_a(), ts(10));
        // A switches to controlled and re-checks, then nominates.
        let switched = parse(&check(0x43, Some(9), Some(IceRole::Controlled), true)).expect("ok");
        note_message(&switched, agent_a(), agent_b(), ts(30));
        let reply = parse(&success(0x43)).expect("parses");
        note_message(&reply, agent_b(), agent_a(), ts(40));

        let ice = report().ice_summary();
        assert_eq!(ice.role_conflicts_total, 1, "the conflict still happened");
        assert_eq!(ice.role_conflicts[0].role, Some(IceRole::Controlling));
        assert!(
            ice.role_conflicts[0].resolved,
            "a pair was nominated afterwards, so ICE fixed it itself"
        );
        assert_eq!(ice.nominated_total, 1);
        reset();
    }

    /// The report's row cap must bite exactly, and the totals beside it must
    /// stay exact past the point it does (D17).
    #[test]
    #[serial_test::serial(stun_store)]
    fn nominations_past_the_row_cap_are_counted_rather_than_listed() {
        reset();
        let extra = 5u16;
        for n in 0..(MAX_ICE_ROWS as u16 + extra) {
            let remote: SocketAddr = format!("203.0.113.9:{}", 16000 + n)
                .parse()
                .expect("valid addr");
            // A distinct transaction ID per check, or the tracker would fold
            // them all into one retransmitted request.
            let mut bytes = check(0x00, Some(1), Some(IceRole::Controlling), true);
            bytes[8..20].copy_from_slice(&[
                (n >> 8) as u8,
                n as u8,
                0x5a,
                0x5a,
                0x5a,
                0x5a,
                0x5a,
                0x5a,
                0x5a,
                0x5a,
                0x5a,
                0x5a,
            ]);
            let request = parse(&bytes).expect("parses");
            note_message(&request, agent_a(), remote, ts(i64::from(n)));
            let mut reply = success(0x00);
            reply[8..20].copy_from_slice(&bytes[8..20]);
            let response = parse(&reply).expect("parses");
            note_message(&response, remote, agent_a(), ts(i64::from(n) + 1));
        }

        let ice = report().ice_summary();
        assert_eq!(ice.nominated.len(), MAX_ICE_ROWS, "the cap holds the list");
        assert_eq!(
            ice.nominated_total,
            u64::from(MAX_ICE_ROWS as u16 + extra),
            "and the total stays exact past it"
        );
        assert_eq!(ice.nominated_dropped(), u64::from(extra));
        reset();
    }

    /// Two agents in the ordinary configuration are not a conflict. Without
    /// this the finding would fire on every healthy ICE exchange there is.
    #[test]
    #[serial_test::serial(stun_store)]
    fn opposite_roles_are_not_a_conflict() {
        reset();
        let from_a = parse(&check(0x51, Some(9), Some(IceRole::Controlling), false)).expect("ok");
        note_message(&from_a, agent_a(), agent_b(), ts(0));
        let from_b = parse(&check(0x52, Some(8), Some(IceRole::Controlled), false)).expect("ok");
        note_message(&from_b, agent_b(), agent_a(), ts(10));

        let ice = report().ice_summary();
        assert_eq!(ice.checks, 2);
        assert_eq!(ice.role_conflicts_total, 0);
        reset();
    }
}

#[cfg(test)]
mod relay_attribution_tests {
    use super::allocation_tracking_tests::relayed_rtp;
    use super::turn_tests::ts;
    use super::*;

    fn client() -> SocketAddr {
        "192.0.2.10:50000".parse().expect("valid addr")
    }
    fn server() -> SocketAddr {
        "198.51.100.20:3478".parse().expect("valid addr")
    }
    fn peer() -> SocketAddr {
        "203.0.113.9:16000".parse().expect("valid addr")
    }

    /// An Allocate that succeeds with a 60-second lifetime, followed by a
    /// ChannelBind for `channel` naming `peer()`.
    fn allocate_and_bind(channel: u16) {
        // Allocate Request / success with XOR-RELAYED-ADDRESS 198.51.100.77:49160
        // and LIFETIME 60, written as the bytes that appear on the wire.
        let req: Vec<u8> = vec![
            0x00, 0x03, 0x00, 0x00, // Allocate Request, no attributes
            0x21, 0x12, 0xa4, 0x42, // magic cookie
            0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1,
        ];
        note_message(&parse(&req).expect("parses"), client(), server(), ts(0));
        let resp: Vec<u8> = vec![
            0x01, 0x03, 0x00, 0x14, // Allocate success, 20 bytes of attributes
            0x21, 0x12, 0xa4, 0x42, // magic cookie
            0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0x00, 0x16,
            0x00, 0x08, // XOR-RELAYED-ADDRESS, 8 bytes
            0x00, 0x01, // reserved, family IPv4
            0xe1, 0x1a, // port 49160 (0xc008) ^ 0x2112
            // 198.51.100.77 ^ 21 12 a4 42
            0xe7, 0x21, 0xc0, 0x0f, //
            0x00, 0x0d, 0x00, 0x04, // LIFETIME, 4 bytes
            0x00, 0x00, 0x00, 0x3c, // 60 seconds
        ];
        note_message(&parse(&resp).expect("parses"), server(), client(), ts(10));

        // ChannelBind Request naming CHANNEL-NUMBER and XOR-PEER-ADDRESS.
        let mut bind: Vec<u8> = vec![
            0x00, 0x09, 0x00, 0x14, // ChannelBind Request, 20 bytes of attributes
            0x21, 0x12, 0xa4, 0x42, // magic cookie
            0xb2, 0xb2, 0xb2, 0xb2, 0xb2, 0xb2, 0xb2, 0xb2, 0xb2, 0xb2, 0xb2, 0xb2, 0x00, 0x0c,
            0x00, 0x02, // CHANNEL-NUMBER, 2 bytes
        ];
        bind.extend_from_slice(&channel.to_be_bytes());
        bind.extend_from_slice(&[0x00, 0x00]); // padding to a 4-byte boundary
        bind.extend_from_slice(&[
            0x00, 0x12, 0x00, 0x08, // XOR-PEER-ADDRESS, 8 bytes
            0x00, 0x01, // reserved, family IPv4
            0x1f, 0x92, // port 16000 (0x3e80) ^ 0x2112
            // 203.0.113.9 ^ 21 12 a4 42
            0xea, 0x12, 0xd5, 0x4b,
        ]);
        note_message(&parse(&bind).expect("parses"), client(), server(), ts(20));
        let bind_ok: Vec<u8> = vec![
            0x01, 0x09, 0x00, 0x00, // ChannelBind success, no attributes
            0x21, 0x12, 0xa4, 0x42, // magic cookie
            0xb2, 0xb2, 0xb2, 0xb2, 0xb2, 0xb2, 0xb2, 0xb2, 0xb2, 0xb2, 0xb2, 0xb2,
        ];
        note_message(
            &parse(&bind_ok).expect("parses"),
            server(),
            client(),
            ts(28),
        );
    }

    /// The literal bytes above must decode to the addresses they claim, or
    /// every assertion below could be met by a decoder producing nonsense.
    #[test]
    #[serial_test::serial(stun_store)]
    fn the_literal_turn_bytes_decode_to_the_addresses_they_encode() {
        reset();
        allocate_and_bind(0x4001);
        let alloc = &report().allocations[0];
        assert_eq!(
            alloc.relayed_address.map(|a| a.to_string()).as_deref(),
            Some("198.51.100.77:49160")
        );
        assert_eq!(alloc.channels[0].peer, Some(peer()));
        reset();
    }

    /// The whole of gap 2: a relayed stream must be reachable from the
    /// allocation that carried it, by the socket pair and SSRC the stream
    /// store already has.
    #[test]
    #[serial_test::serial(stun_store)]
    fn a_relayed_stream_is_attributable_to_its_channel_and_allocation() {
        reset();
        allocate_and_bind(0x4001);
        note_channel_data(
            client(),
            server(),
            &relayed_rtp(0x4001, 0x1122_3344),
            ts(30_000),
        );
        note_channel_data(
            server(),
            client(),
            &relayed_rtp(0x4001, 0x5566_7788),
            ts(30_020),
        );

        let path = relay_path_for(client(), server(), 0x1122_3344)
            .expect("the relayed stream must find its allocation");
        assert_eq!(path.client, client());
        assert_eq!(path.server, server());
        assert_eq!(
            path.relayed_address.map(|a| a.to_string()).as_deref(),
            Some("198.51.100.77:49160")
        );
        assert_eq!(path.channel, 0x4001);
        assert_eq!(path.peer, Some(peer()));
        assert!(!path.lapsed, "the grant had not run out yet");

        // And in the reverse direction, because a relayed call has two streams
        // and only one of them is addressed client-to-server.
        let back = relay_path_for(server(), client(), 0x5566_7788).expect("the other direction");
        assert_eq!(back.channel, 0x4001);

        let alloc = &report().allocations[0];
        assert_eq!(alloc.relayed_frames(), 2);
        assert_eq!(alloc.relayed_ssrcs(), vec![0x1122_3344, 0x5566_7788]);
        assert!(
            alloc.channels[0].bound,
            "the ChannelBind was seen to succeed"
        );
        reset();
    }

    /// The lapsed-allocation finding must be able to name the media that died
    /// with the relay. Before this it could say an allocation lapsed and not
    /// one packet that was on it.
    #[test]
    #[serial_test::serial(stun_store)]
    fn a_lapsed_allocation_names_the_media_that_died_with_it() {
        reset();
        allocate_and_bind(0x4001);
        note_channel_data(
            client(),
            server(),
            &relayed_rtp(0x4001, 0x1122_3344),
            ts(90_000),
        );

        let report = report();
        assert_eq!(report.lapsed_allocations().count(), 1);
        assert_eq!(report.lapsed_relayed_streams(), 1);
        let label = report.allocations[0]
            .relayed_media_label()
            .expect("the media must be nameable");
        assert!(label.contains("0x11223344"), "{label}");
        assert!(label.contains("0x4001"), "{label}");
        // And the stream itself carries the verdict, so a per-call surface
        // does not have to re-derive it from the capture-level finding.
        let path = relay_path_for(client(), server(), 0x1122_3344).expect("attributed");
        assert!(path.lapsed);
        reset();
    }

    /// Media that merely shares an address with a relay is not media the
    /// relay carried. Attributing it would be the confident wrong answer the
    /// SSRC half of the join exists to prevent.
    #[test]
    #[serial_test::serial(stun_store)]
    fn an_ssrc_never_seen_in_a_channel_is_not_attributed() {
        reset();
        allocate_and_bind(0x4001);
        note_channel_data(
            client(),
            server(),
            &relayed_rtp(0x4001, 0x1122_3344),
            ts(30_000),
        );
        assert!(
            relay_path_for(client(), server(), 0xdead_beef).is_none(),
            "an SSRC that never crossed the relay must not claim to have"
        );
        reset();
    }

    /// RTCP relayed on the same channel must not be filed as a media stream:
    /// its bytes 8..12 are not an SSRC in the sense the stream store means.
    #[test]
    #[serial_test::serial(stun_store)]
    fn relayed_rtcp_contributes_no_stream() {
        reset();
        allocate_and_bind(0x4001);
        // A ChannelData frame wrapping a minimal RTCP receiver report (PT 201).
        let frame: Vec<u8> = vec![
            0x40, 0x01, 0x00, 0x08, // channel 0x4001, 8 bytes of application data
            0x80, 0xc9, 0x00, 0x01, // V=2, PT=201 (RR), length 1
            0x11, 0x22, 0x33, 0x44, // sender SSRC
        ];
        note_channel_data(client(), server(), &frame, ts(30_000));

        let alloc = &report().allocations[0];
        assert_eq!(
            alloc.relayed_frames(),
            1,
            "the frame still counts as relayed"
        );
        assert!(
            alloc.relayed_ssrcs().is_empty(),
            "but it is not a media stream"
        );
        reset();
    }

    /// The retention cap must bite exactly, and must stay countable past the
    /// point it does (D17).
    #[test]
    #[serial_test::serial(stun_store)]
    fn channels_past_the_cap_are_counted_rather_than_stored() {
        reset();
        allocate_and_bind(0x4001);
        for n in 0..(MAX_CHANNELS_PER_ALLOCATION as u16 + 4) {
            note_channel_data(
                client(),
                server(),
                &relayed_rtp(0x4001 + n, 0x0100_0000 + u32::from(n)),
                ts(1_000 + i64::from(n)),
            );
        }
        let alloc = &report().allocations[0];
        assert_eq!(alloc.channels.len(), MAX_CHANNELS_PER_ALLOCATION);
        assert_eq!(
            alloc.unattributed_frames, 4,
            "the four frames past the cap must still be counted"
        );
        let label = alloc.relayed_media_label().expect("a label");
        assert!(
            label.contains("a sample"),
            "the report must say the list is partial: {label}"
        );
        reset();
    }

    /// A relayed frame must never CREATE an allocation, and must never
    /// attribute to one it did not cross.
    #[test]
    #[serial_test::serial(stun_store)]
    fn a_frame_with_no_allocation_attributes_to_nothing() {
        reset();
        note_channel_data(client(), server(), &relayed_rtp(0x4001, 1), ts(0));
        assert!(report().allocations.is_empty());
        assert!(relay_path_for(client(), server(), 1).is_none());
        reset();
    }
}
