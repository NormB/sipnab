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
pub mod hostile;
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
#[cfg(test)]
mod tests {
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
