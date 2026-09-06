// SPDX-License-Identifier: MIT OR Apache-2.0

//! SIP protocol parsing, dialog state tracking, and filter DSL.
//!
//! Provides zero-copy SIP message parsing, lazy header extraction,
//! response code intelligence, dialog state tracking, and a declarative
//! filter DSL for matching calls.
//!
//! Core types: [`SipMessage`], [`SipDialog`](dialog::SipDialog),
//! [`DialogState`](dialog::DialogState), [`SipMethod`],
//! [`FilterExpr`](dsl::FilterExpr).

pub mod charging_vector;
pub mod diagnosis;
pub mod dialog;
pub(crate) mod dialog_state_machine;
pub mod dialog_store;
pub mod dsl;
pub mod lint;
#[cfg(feature = "native")]
pub mod matcher;
pub mod message;
pub mod method;
pub mod parser;
pub mod response_codes;
pub mod sdp;
pub mod sdp_timeline;
pub mod session_id;
pub mod siprec;
#[cfg(feature = "tls")]
pub mod stir_shaken;
pub mod timing;

pub use message::{SipHeader, SipMessage};
pub use method::SipMethod;
pub use parser::parse_sip;
pub use response_codes::explain_response_code;
pub use sdp::{SdpConnection, SdpCrypto, SdpDirection, SdpMedia, SdpSession, parse_sdp};

/// Quick check whether `data` looks like the start of a SIP message.
///
/// # Arguments
///
/// * `data` — raw captured bytes to sniff (typically a UDP payload or the
///   start of a TCP stream segment).
///
/// # Returns
///
/// Returns `true` if the data begins with a SIP response line (`SIP/2.0 `)
/// or a SIP request line (`METHOD SP ... SIP/2.0`). Only inspects the first
/// line — does **not** validate the entire message. Inputs shorter than
/// 8 bytes always return `false`.
///
/// # One sniffer, not two
///
/// This delegates to [`parser::starts_sip_message`] rather than carrying its
/// own copy. It used to walk a FIXED method table, so a request whose method
/// was not in that list — every extension method, and the ones RFCs keep
/// adding — was not SIP as far as this function was concerned, while the
/// parser accepted it. Callers on the TCP framing path, the WASM entry point
/// and the HEP and TLS paths therefore classified traffic by a narrower rule
/// than the one that would later parse it, and dropping extension methods
/// wholesale is the defect #84 already found elsewhere.
///
/// The measured effect on the local corpus is ZERO additional messages: that
/// traffic uses no method outside the old table. This is consistency, not a
/// recovered loss, and must not be described as one — the value is that a
/// method added to the parser cannot leave a second sniffer behind (#95).
pub fn is_sip_message(data: &[u8]) -> bool {
    parser::starts_sip_message(data)
}

/// Tests for the `is_sip_message` first-line sniffer.
/// The `Expires` value a REGISTER or its response is asking for or granting.
///
/// Shared: the diagnosis layer reads it to report a shortened grant, and the
/// dialog state machine reads it to tell a registration from a de-registration.
/// One reader would have been enough until `Expired` turned out to be a state
/// nothing could reach.
///
/// RFC 3261 §10.2.1.1 allows the interval to arrive two ways: an `Expires`
/// header, or an `expires` parameter on the `Contact`. The parameter wins where
/// both appear, because it is the per-binding value and the header is only the
/// default for bindings that do not carry one.
pub(crate) fn registration_expiry(msg: &SipMessage) -> Option<u32> {
    if let Some(contact) = msg.contact() {
        // Header parameters begin AFTER the addr-spec. RFC 3261 §25.1:
        // `SIP-URI = "sip:" [userinfo] hostport uri-parameters [headers]` and
        // `contact-param = (name-addr / addr-spec) *(SEMI contact-params)` —
        // so everything between `<` and `>` is URI parameters and belongs to
        // the URI, not to the Contact.
        //
        // Reading the raw value meant a conformant
        // `<sip:alice@host;expires=60>;expires=3600` took the URI's 60 and
        // reported "Registration granted 60s against 3600s requested" — a
        // finding manufactured out of a parameter that says nothing about the
        // binding. §10.2.1.1 puts the binding lifetime on the HEADER
        // parameter.
        let params = match contact.find('>') {
            Some(close) => &contact[close + 1..],
            // A bare addr-spec has no brackets; RFC 3261 §20.10 then forbids
            // it from carrying URI parameters at all, so every `;` is a header
            // parameter and the whole value is the right thing to scan.
            None => contact,
        };
        for param in params.split(';').skip(1) {
            // A Contact carries valueless parameters as often as not -- `;ob`
            // from an outbound registration, `;lr`, `;isfocus`. This used `?`,
            // which returned None from the WHOLE function on the first one, so
            // the `Expires` header fallback below never ran and an unregister
            // from a pjsip phone read as no expiry at all. Both spellings have
            // to work; skipping is what makes the fallback reachable.
            let Some((name, value)) = param.split_once('=') else {
                continue;
            };
            if name.trim().eq_ignore_ascii_case("expires") {
                return value.trim().trim_matches('"').parse().ok();
            }
        }
    }
    msg.header("Expires")?.trim().parse().ok()
}

#[cfg(test)]
mod tests {
    use crate::net::TransportProto;
    use crate::sip::parser::parse_sip;
    use chrono::Utc;
    use std::net::{IpAddr, Ipv4Addr};

    /// A REGISTER carrying `contact` and no `Expires` header.
    fn contact_msg(contact: &str) -> SipMessage {
        build(contact, None)
    }

    /// A REGISTER carrying `contact` and an `Expires` header.
    fn contact_msg_with_expires(contact: &str, expires: &str) -> SipMessage {
        build(contact, Some(expires))
    }

    /// Parse a minimal REGISTER so the tests exercise the real accessors
    /// rather than a hand-built struct.
    fn build(contact: &str, expires: Option<&str>) -> SipMessage {
        let mut raw = String::from("REGISTER sip:example.com SIP/2.0\r\n");
        raw.push_str("From: <sip:alice@example.com>;tag=t1\r\n");
        raw.push_str("To: <sip:alice@example.com>\r\n");
        raw.push_str("Call-ID: reg-test@example.com\r\n");
        raw.push_str("CSeq: 1 REGISTER\r\n");
        raw.push_str(&format!("Contact: {contact}\r\n"));
        if let Some(e) = expires {
            raw.push_str(&format!("Expires: {e}\r\n"));
        }
        raw.push_str("Content-Length: 0\r\n\r\n");
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        parse_sip(
            raw.as_bytes(),
            Utc::now(),
            ip,
            ip,
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("the fixture must parse")
    }

    /// A URI parameter is not the binding lifetime.
    ///
    /// RFC 3261 §25.1 puts everything between `<` and `>` in
    /// `uri-parameters`; §10.2.1.1 puts the binding lifetime on the Contact
    /// HEADER parameter. Reading the raw value took the URI's `expires` and
    /// reported a registration granted for 60s against 3600s requested — a
    /// finding fabricated from a parameter about the URI.
    #[test]
    fn a_uri_expires_parameter_is_not_the_binding_lifetime() {
        let msg = contact_msg("<sip:alice@10.0.0.1;expires=60;transport=udp>;expires=3600");
        assert_eq!(registration_expiry(&msg), Some(3600));
    }

    /// A URI parameter alone leaves the header fallback reachable.
    ///
    /// The shape that lost the expiry entirely: `expires=0>` failed to parse,
    /// the function returned early, and the `Expires:` header beneath it was
    /// never consulted — so an unregister read as no expiry at all.
    #[test]
    fn a_uri_expires_alone_falls_through_to_the_expires_header() {
        let msg = contact_msg_with_expires("<sip:alice@10.0.0.1;expires=0>", "3600");
        assert_eq!(registration_expiry(&msg), Some(3600));
    }

    /// The header parameter still wins over the `Expires` header.
    ///
    /// The regression guard for §10.2.1.1's precedence rule, which the fix
    /// must not invert.
    #[test]
    fn the_contact_header_parameter_still_beats_the_expires_header() {
        let msg = contact_msg_with_expires("<sip:alice@10.0.0.1>;expires=60", "3600");
        assert_eq!(registration_expiry(&msg), Some(60));
    }

    /// A bare addr-spec carries header parameters directly.
    ///
    /// RFC 3261 §20.10 forbids a Contact without angle brackets from carrying
    /// URI parameters, so every `;` in it is a header parameter. Skipping to
    /// after a `>` that is not there must not skip the whole value.
    #[test]
    fn a_bare_addr_spec_contact_still_yields_its_expires() {
        let msg = contact_msg("sip:alice@10.0.0.1;expires=120");
        assert_eq!(registration_expiry(&msg), Some(120));
    }

    /// An unregister is still an unregister.
    #[test]
    fn a_zero_expiry_is_read_as_zero() {
        let msg = contact_msg("<sip:alice@10.0.0.1>;expires=0");
        assert_eq!(registration_expiry(&msg), Some(0));
    }

    use super::*;

    /// An extension method is SIP here too, because this is now the same
    /// sniffer the parser uses (#95).
    ///
    /// The old fixed method table said no to anything it had not been told
    /// about, so the TCP framing path, the WASM entry point and the HEP and
    /// TLS paths classified traffic by a narrower rule than the one that would
    /// later parse it. Zero additional messages on the local corpus — this
    /// pins the CONSISTENCY, not a recovered loss.
    #[test]
    fn an_extension_method_is_sip_to_both_sniffers() {
        // SERVICE: a real SIP method, and one the old fourteen-entry table
        // did not list. (PUBLISH would NOT demonstrate anything — it was in
        // that table.)
        let raw = b"SERVICE sip:presentity@example.com SIP/2.0\r\nVia: SIP/2.0/UDP h\r\n\r\n";
        assert!(
            is_sip_message(raw),
            "an extension method must be SIP to the sniffer the framing paths use"
        );
        assert_eq!(
            is_sip_message(raw),
            parser::starts_sip_message(raw),
            "the two must never disagree: one classifies, the other parses"
        );

        // And the rejections still hold — delegation must not have widened it
        // into accepting binary media. RTP opens 0x80.
        let rtp = [0x80u8, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0];
        assert!(!is_sip_message(&rtp), "RTP must not sniff as SIP");
        assert_eq!(is_sip_message(&rtp), parser::starts_sip_message(&rtp));
    }

    /// An INVITE request line is detected as SIP.
    #[test]
    fn detect_invite_request() {
        let data = b"INVITE sip:bob@example.com SIP/2.0\r\nVia: SIP/2.0/UDP ...\r\n\r\n";
        assert!(is_sip_message(data));
    }

    /// A `SIP/2.0` status line is detected as SIP.
    #[test]
    fn detect_response() {
        let data = b"SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP ...\r\n\r\n";
        assert!(is_sip_message(data));
    }

    /// A REGISTER request line is detected as SIP.
    #[test]
    fn detect_register() {
        let data = b"REGISTER sip:registrar.example.com SIP/2.0\r\n\r\n";
        assert!(is_sip_message(data));
    }

    /// HTTP, free text, empty, and too-short inputs are all rejected.
    #[test]
    fn reject_non_sip() {
        assert!(!is_sip_message(b"GET / HTTP/1.1\r\n\r\n"));
        assert!(!is_sip_message(b"Hello world"));
        assert!(!is_sip_message(b""));
        assert!(!is_sip_message(b"SIP"));
    }

    /// Non-text bytes with no SIP first line are rejected.
    #[test]
    fn reject_binary_garbage() {
        assert!(!is_sip_message(&[
            0xFF, 0xFE, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05
        ]));
    }

    /// The version token must be SP-anchored: `ASIP/2.0` glued onto the URI
    /// (matched only by an unanchored `ends_with`) must not be sniffed as SIP.
    #[test]
    fn reject_unanchored_version_token() {
        assert!(!is_sip_message(b"INVITE sip:alice ASIP/2.0\r\n\r\n"));
    }
}
