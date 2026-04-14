//! SIP message parsing and analysis for sipnab.
//!
//! Provides zero-copy SIP message parsing, lazy header extraction, and
//! response code intelligence. The parser operates on `&[u8]` byte slices
//! from the capture engine's [`ParsedPacket`](crate::capture::ParsedPacket)
//! payloads.

pub mod dialog;
pub mod dialog_store;
pub mod dsl;
pub mod matcher;
pub mod message;
pub mod parser;
pub mod response_codes;
pub mod sdp;
pub mod sdp_timeline;
pub mod siprec;
pub mod stir_shaken;
pub mod timing;

pub use message::{SipHeader, SipMessage};
pub use parser::parse_sip;
pub use response_codes::explain_response_code;
pub use sdp::{SdpConnection, SdpCrypto, SdpDirection, SdpMedia, SdpSession, parse_sdp};

/// Known SIP request methods for quick first-line detection.
const SIP_METHODS: &[&[u8]] = &[
    b"INVITE",
    b"ACK",
    b"BYE",
    b"CANCEL",
    b"REGISTER",
    b"OPTIONS",
    b"PRACK",
    b"SUBSCRIBE",
    b"NOTIFY",
    b"PUBLISH",
    b"INFO",
    b"REFER",
    b"MESSAGE",
    b"UPDATE",
];

/// Quick check whether `data` looks like the start of a SIP message.
///
/// Returns `true` if the data begins with a SIP response line (`SIP/2.0 `)
/// or a SIP request line (`METHOD SP ... SIP/2.0`). Only inspects the first
/// line — does **not** validate the entire message.
pub fn is_sip_message(data: &[u8]) -> bool {
    if data.len() < 8 {
        return false;
    }

    // Response: starts with "SIP/2.0 "
    if data.starts_with(b"SIP/2.0 ") {
        return true;
    }

    // Request: starts with a known method followed by SP
    for method in SIP_METHODS {
        if data.len() > method.len() && data.starts_with(method) && data[method.len()] == b' ' {
            // Verify "SIP/2.0" appears in the first line
            if let Some(line_end) = find_crlf(data) {
                let first_line = &data[..line_end];
                if first_line.ends_with(b"SIP/2.0") {
                    return true;
                }
            }
            return false;
        }
    }

    false
}

/// Find the position of the first `\r\n` in `data`.
fn find_crlf(data: &[u8]) -> Option<usize> {
    data.windows(2).position(|w| w == b"\r\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_invite_request() {
        let data = b"INVITE sip:bob@example.com SIP/2.0\r\nVia: SIP/2.0/UDP ...\r\n\r\n";
        assert!(is_sip_message(data));
    }

    #[test]
    fn detect_response() {
        let data = b"SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP ...\r\n\r\n";
        assert!(is_sip_message(data));
    }

    #[test]
    fn detect_register() {
        let data = b"REGISTER sip:registrar.example.com SIP/2.0\r\n\r\n";
        assert!(is_sip_message(data));
    }

    #[test]
    fn reject_non_sip() {
        assert!(!is_sip_message(b"GET / HTTP/1.1\r\n\r\n"));
        assert!(!is_sip_message(b"Hello world"));
        assert!(!is_sip_message(b""));
        assert!(!is_sip_message(b"SIP"));
    }

    #[test]
    fn reject_binary_garbage() {
        assert!(!is_sip_message(&[
            0xFF, 0xFE, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05
        ]));
    }
}
