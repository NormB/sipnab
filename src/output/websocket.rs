// SPDX-License-Identifier: MIT OR Apache-2.0

//! The server half of [RFC 6455](https://www.rfc-editor.org/rfc/rfc6455.html)
//! WebSocket that the live audio route needs: the handshake's accept key, the
//! frames a server sends, and the client frames it must answer.
//!
//! Written here rather than taken from a WebSocket crate because the route
//! only ever sends: binary audio frames, a text header, and a close. The one
//! primitive the handshake needs, SHA-1, is already in every build that has
//! the REST API, through rustls.

/// The GUID [RFC 6455 section 1.3](https://www.rfc-editor.org/rfc/rfc6455.html#section-1.3)
/// appends to the client's key.
const GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// A frame's opcode, [RFC 6455 section 5.2](https://www.rfc-editor.org/rfc/rfc6455.html#section-5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Opcode {
    /// A UTF-8 text message.
    Text,
    /// A binary message.
    Binary,
    /// The closing handshake.
    Close,
    /// A ping, to be answered with a pong.
    Ping,
    /// A pong.
    Pong,
}

impl Opcode {
    /// The four-bit code.
    fn code(self) -> u8 {
        match self {
            Self::Text => 0x1,
            Self::Binary => 0x2,
            Self::Close => 0x8,
            Self::Ping => 0x9,
            Self::Pong => 0xA,
        }
    }

    /// The opcode for a four-bit code, or `None` for one this server does
    /// not take (a continuation, or a reserved code).
    fn of(code: u8) -> Option<Self> {
        match code {
            0x1 => Some(Self::Text),
            0x2 => Some(Self::Binary),
            0x8 => Some(Self::Close),
            0x9 => Some(Self::Ping),
            0xA => Some(Self::Pong),
            _ => None,
        }
    }
}

/// The `Sec-WebSocket-Accept` value for a client's `Sec-WebSocket-Key`:
/// base64 of the SHA-1 of the key followed by the GUID.
#[must_use]
pub fn accept_key(key: &str) -> String {
    use base64::Engine as _;
    let mut input = key.trim().as_bytes().to_vec();
    input.extend_from_slice(GUID.as_bytes());
    let digest = ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, &input);
    base64::engine::general_purpose::STANDARD.encode(digest.as_ref())
}

/// One whole, unfragmented frame a server sends: never masked, which
/// [RFC 6455 section 5.1](https://www.rfc-editor.org/rfc/rfc6455.html#section-5.1)
/// forbids a server to do.
#[must_use]
pub fn frame(opcode: Opcode, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 10);
    out.push(0x80 | opcode.code());
    let len = payload.len();
    if len < 126 {
        out.push(len as u8);
    } else if let Ok(short) = u16::try_from(len) {
        out.push(126);
        out.extend_from_slice(&short.to_be_bytes());
    } else {
        out.push(127);
        out.extend_from_slice(&(len as u64).to_be_bytes());
    }
    out.extend_from_slice(payload);
    out
}

/// A close frame with `code` and a reason.
#[must_use]
pub fn close(code: u16, reason: &str) -> Vec<u8> {
    let mut payload = code.to_be_bytes().to_vec();
    payload.extend_from_slice(reason.as_bytes());
    frame(Opcode::Close, &payload)
}

/// A client frame, decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientFrame {
    /// What it is.
    pub opcode: Opcode,
    /// Its payload, unmasked.
    pub payload: Vec<u8>,
}

/// The largest client frame read. A client of the audio route sends only
/// control frames, whose payload [RFC 6455 section 5.5](https://www.rfc-editor.org/rfc/rfc6455.html#section-5.5)
/// caps at 125 bytes; this leaves room for a short text message.
pub const MAX_CLIENT_FRAME: usize = 4096;

/// Decode one client frame from the front of `buf`.
///
/// `Ok(None)`: `buf` does not hold a whole frame yet. `Ok(Some((frame,
/// used)))`: a frame, and how many bytes of `buf` it took.
///
/// # Errors
///
/// What makes the frame one to close the connection over: unmasked (a client
/// MUST mask, section 5.1), fragmented, an unknown opcode, or longer than
/// [`MAX_CLIENT_FRAME`].
pub fn parse_client_frame(buf: &[u8]) -> Result<Option<(ClientFrame, usize)>, &'static str> {
    let [first, second, rest @ ..] = buf else {
        return Ok(None);
    };
    if first & 0x80 == 0 {
        return Err("a fragmented frame");
    }
    let opcode = Opcode::of(first & 0x0F).ok_or("an unknown opcode")?;
    if second & 0x80 == 0 {
        return Err("an unmasked client frame");
    }
    let (len, header) = match second & 0x7F {
        126 => match rest {
            [a, b, ..] => (usize::from(u16::from_be_bytes([*a, *b])), 4),
            _ => return Ok(None),
        },
        127 => match rest.get(..8) {
            Some(bytes) => {
                let mut be = [0u8; 8];
                be.copy_from_slice(bytes);
                (
                    usize::try_from(u64::from_be_bytes(be)).unwrap_or(usize::MAX),
                    10,
                )
            }
            None => return Ok(None),
        },
        n => (usize::from(n), 2),
    };
    if len > MAX_CLIENT_FRAME {
        return Err("a frame longer than this server reads");
    }
    let Some(mask) = buf.get(header..header + 4) else {
        return Ok(None);
    };
    let start = header + 4;
    let Some(masked) = buf.get(start..start + len) else {
        return Ok(None);
    };
    let payload = masked
        .iter()
        .enumerate()
        .map(|(i, b)| b ^ mask[i % 4])
        .collect();
    Ok(Some((ClientFrame { opcode, payload }, start + len)))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The worked example of [RFC 6455 section 1.3](https://www.rfc-editor.org/rfc/rfc6455.html#section-1.3).
    #[test]
    fn the_accept_key_is_the_rfc_example() {
        assert_eq!(
            accept_key("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    /// Section 5.7's examples: an unmasked "Hello", and the 256-byte and
    /// 65536-byte binary frames' headers.
    #[test]
    fn frames_carry_the_rfc_headers() {
        assert_eq!(
            frame(Opcode::Text, b"Hello"),
            [0x81, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f]
        );
        assert_eq!(
            frame(Opcode::Binary, &[0; 256])[..4],
            [0x82, 0x7E, 0x01, 0x00]
        );
        assert_eq!(
            frame(Opcode::Binary, &[0; 65536])[..10],
            [0x82, 0x7F, 0, 0, 0, 0, 0, 1, 0, 0]
        );
        assert_eq!(frame(Opcode::Binary, &[0; 125])[..2], [0x82, 125]);
        // 126 is the first length that takes the 16-bit form.
        assert_eq!(
            frame(Opcode::Binary, &[0; 126])[..4],
            [0x82, 0x7E, 0x00, 0x7E]
        );
        assert_eq!(
            frame(Opcode::Binary, &[0; 65535])[..4],
            [0x82, 0x7E, 0xFF, 0xFF]
        );
    }

    /// A close carries its code first.
    #[test]
    fn a_close_carries_its_code() {
        assert_eq!(
            close(1000, "bye"),
            [0x88, 0x05, 0x03, 0xE8, b'b', b'y', b'e']
        );
    }

    /// Section 5.7's masked "Hello" from a client.
    #[test]
    fn a_masked_client_frame_decodes() -> Result<(), &'static str> {
        let wire = [
            0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58,
        ];
        let (got, used) = parse_client_frame(&wire)?.ok_or("a whole frame")?;
        assert_eq!(got.opcode, Opcode::Text);
        assert_eq!(got.payload, b"Hello");
        assert_eq!(used, wire.len());
        for cut in 0..wire.len() {
            assert_eq!(parse_client_frame(&wire[..cut])?, None, "cut at {cut}");
        }
        Ok(())
    }

    /// What a server closes over.
    #[test]
    fn a_bad_client_frame_is_refused() {
        // Unmasked.
        assert!(parse_client_frame(&[0x81, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f]).is_err());
        // Fragmented (FIN clear).
        assert!(parse_client_frame(&[0x01, 0x80, 0, 0, 0, 0]).is_err());
        // Reserved opcode.
        assert!(parse_client_frame(&[0x83, 0x80, 0, 0, 0, 0]).is_err());
        // Longer than the server reads.
        assert!(parse_client_frame(&[0x82, 0xFF, 0, 0, 0, 0, 0, 1, 0, 0]).is_err());
    }
}
