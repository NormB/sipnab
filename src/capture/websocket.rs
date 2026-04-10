//! WebSocket frame unwrapping for SIP-over-WebSocket (RFC 7118).
//!
//! SIP messages transported via WebSocket are wrapped in WebSocket frames.
//! This module strips the frame header (and unmasking, if present) to extract
//! the raw SIP payload for upper-layer parsing.
//!
//! Only text (opcode 1) and binary (opcode 2) frames are considered data
//! frames; control frames (close, ping, pong) are ignored.

use anyhow::{Result, bail};

/// Maximum allowed WebSocket frame payload size (D17 limit: 64 KB).
const MAX_FRAME_SIZE: u64 = 65_536;

/// WebSocket opcodes for data frames.
const OPCODE_TEXT: u8 = 1;
const OPCODE_BINARY: u8 = 2;

/// Common ports where SIP-over-WebSocket traffic is expected.
pub const WS_PORTS: &[u16] = &[80, 443, 8080, 8443];

/// Check if data looks like a WebSocket frame (heuristic).
///
/// Returns `true` if the first two bytes are consistent with a WebSocket
/// data frame: FIN bit set, reserved bits zero, opcode 1 (text) or 2
/// (binary), and enough remaining bytes for the declared payload length.
pub fn is_websocket_frame(data: &[u8]) -> bool {
    if data.len() < 2 {
        return false;
    }

    let byte0 = data[0];
    let byte1 = data[1];

    // FIN must be set, RSV bits must be zero
    let fin = byte0 & 0x80 != 0;
    let rsv = byte0 & 0x70;
    if !fin || rsv != 0 {
        return false;
    }

    let opcode = byte0 & 0x0F;
    if opcode != OPCODE_TEXT && opcode != OPCODE_BINARY {
        return false;
    }

    let masked = byte1 & 0x80 != 0;
    let len7 = (byte1 & 0x7F) as u64;

    // Calculate the minimum header size
    let header_size = header_size(len7, masked);

    // Verify we have at least enough data for the header
    if data.len() < header_size {
        return false;
    }

    // Compute the full payload length and check it fits
    let payload_len = match len7 {
        126 => u16::from_be_bytes([data[2], data[3]]) as u64,
        127 => u64::from_be_bytes([
            data[2], data[3], data[4], data[5], data[6], data[7], data[8], data[9],
        ]),
        n => n,
    };

    if payload_len > MAX_FRAME_SIZE {
        return false;
    }

    let total = header_size as u64 + payload_len;
    data.len() as u64 >= total
}

/// Unwrap a WebSocket frame, returning the payload bytes.
///
/// Returns `Ok(Some(payload))` for text (opcode 1) and binary (opcode 2)
/// data frames. Returns `Ok(None)` for control frames (close, ping, pong).
///
/// # Errors
///
/// Returns an error if:
/// - The data is too short to contain a valid frame header
/// - The declared payload length exceeds the 64 KB limit
/// - The data is truncated (shorter than header + payload)
pub fn unwrap_websocket_frame(data: &[u8]) -> Result<Option<Vec<u8>>> {
    if data.len() < 2 {
        bail!(
            "WebSocket frame too short ({} bytes, need at least 2)",
            data.len()
        );
    }

    let byte0 = data[0];
    let byte1 = data[1];

    let opcode = byte0 & 0x0F;
    let masked = byte1 & 0x80 != 0;
    let len7 = (byte1 & 0x7F) as u64;

    // Control frames: close (8), ping (9), pong (10) — skip
    if opcode >= 8 {
        return Ok(None);
    }

    // Only handle text and binary data frames
    if opcode != OPCODE_TEXT && opcode != OPCODE_BINARY {
        return Ok(None);
    }

    // Determine payload length
    let (payload_len, mut offset) = match len7 {
        126 => {
            if data.len() < 4 {
                bail!(
                    "WebSocket frame truncated: need 4 bytes for extended length, have {}",
                    data.len()
                );
            }
            let len = u16::from_be_bytes([data[2], data[3]]) as u64;
            (len, 4usize)
        }
        127 => {
            if data.len() < 10 {
                bail!(
                    "WebSocket frame truncated: need 10 bytes for 64-bit length, have {}",
                    data.len()
                );
            }
            let len = u64::from_be_bytes([
                data[2], data[3], data[4], data[5], data[6], data[7], data[8], data[9],
            ]);
            (len, 10usize)
        }
        n => (n, 2usize),
    };

    if payload_len > MAX_FRAME_SIZE {
        bail!("WebSocket frame payload too large ({payload_len} bytes, max {MAX_FRAME_SIZE})");
    }

    // Read masking key if present
    let mask_key = if masked {
        if data.len() < offset + 4 {
            bail!(
                "WebSocket frame truncated: need {} bytes for mask key, have {}",
                offset + 4,
                data.len()
            );
        }
        let key = [
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ];
        offset += 4;
        Some(key)
    } else {
        None
    };

    let payload_len = payload_len as usize;
    if data.len() < offset + payload_len {
        bail!(
            "WebSocket frame truncated: need {} bytes total, have {}",
            offset + payload_len,
            data.len()
        );
    }

    let payload_data = &data[offset..offset + payload_len];

    let payload = if let Some(key) = mask_key {
        // XOR unmask
        payload_data
            .iter()
            .enumerate()
            .map(|(i, &b)| b ^ key[i % 4])
            .collect()
    } else {
        payload_data.to_vec()
    };

    Ok(Some(payload))
}

/// Calculate the WebSocket frame header size based on length indicator and mask bit.
fn header_size(len7: u64, masked: bool) -> usize {
    let base = match len7 {
        126 => 4,  // 2 base + 2 extended length
        127 => 10, // 2 base + 8 extended length
        _ => 2,    // 2 base only
    };
    if masked { base + 4 } else { base }
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an unmasked WebSocket text frame with the given payload.
    fn build_unmasked_text_frame(payload: &[u8]) -> Vec<u8> {
        let mut frame = Vec::new();
        // FIN=1, RSV=0, opcode=1 (text)
        frame.push(0x81);

        let len = payload.len();
        if len < 126 {
            frame.push(len as u8); // MASK=0
        } else if len <= 0xFFFF {
            frame.push(126);
            frame.extend_from_slice(&(len as u16).to_be_bytes());
        } else {
            frame.push(127);
            frame.extend_from_slice(&(len as u64).to_be_bytes());
        }

        frame.extend_from_slice(payload);
        frame
    }

    /// Build a masked WebSocket text frame with the given payload and mask key.
    fn build_masked_text_frame(payload: &[u8], mask_key: [u8; 4]) -> Vec<u8> {
        let mut frame = Vec::new();
        // FIN=1, RSV=0, opcode=1 (text)
        frame.push(0x81);

        let len = payload.len();
        if len < 126 {
            frame.push(0x80 | len as u8); // MASK=1
        } else if len <= 0xFFFF {
            frame.push(0x80 | 126);
            frame.extend_from_slice(&(len as u16).to_be_bytes());
        } else {
            frame.push(0x80 | 127);
            frame.extend_from_slice(&(len as u64).to_be_bytes());
        }

        frame.extend_from_slice(&mask_key);

        // XOR the payload with the mask key
        for (i, &b) in payload.iter().enumerate() {
            frame.push(b ^ mask_key[i % 4]);
        }

        frame
    }

    #[test]
    fn unwrap_unmasked_text_frame() {
        let payload = b"INVITE sip:bob@example.com SIP/2.0\r\n\r\n";
        let frame = build_unmasked_text_frame(payload);

        assert!(is_websocket_frame(&frame));
        let result = unwrap_websocket_frame(&frame).unwrap();
        assert_eq!(result, Some(payload.to_vec()));
    }

    #[test]
    fn unwrap_masked_frame() {
        let payload = b"SIP/2.0 200 OK\r\n\r\n";
        let mask_key = [0x37, 0xFA, 0x21, 0x3D];
        let frame = build_masked_text_frame(payload, mask_key);

        assert!(is_websocket_frame(&frame));
        let result = unwrap_websocket_frame(&frame).unwrap();
        assert_eq!(result, Some(payload.to_vec()));
    }

    #[test]
    fn unwrap_extended_length_126() {
        // Create a payload > 125 bytes to trigger 126-format length
        let payload = vec![b'A'; 200];
        let frame = build_unmasked_text_frame(&payload);

        // Verify the frame uses 126-format
        assert_eq!(frame[1] & 0x7F, 126);

        assert!(is_websocket_frame(&frame));
        let result = unwrap_websocket_frame(&frame).unwrap();
        assert_eq!(result, Some(payload));
    }

    #[test]
    fn control_frame_close_returns_none() {
        // opcode 8 = close, FIN=1
        let frame = vec![0x88, 0x02, 0x03, 0xE8]; // close with status 1000

        let result = unwrap_websocket_frame(&frame).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn oversized_frame_returns_error() {
        let mut frame = Vec::new();
        // FIN=1, opcode=1 (text)
        frame.push(0x81);
        // 127-format length
        frame.push(127);
        // Payload length = 100_000 (exceeds 64KB limit)
        frame.extend_from_slice(&100_000u64.to_be_bytes());
        // Don't need actual payload data — the length check happens first
        frame.extend_from_slice(&[0u8; 100]);

        let result = unwrap_websocket_frame(&frame);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("too large"), "error: {err_msg}");
    }

    #[test]
    fn truncated_frame_returns_error() {
        // Valid header declaring 50-byte payload, but only 10 bytes of data
        let mut frame = Vec::new();
        frame.push(0x81); // FIN=1, text
        frame.push(50); // 50-byte payload
        frame.extend_from_slice(&[0u8; 10]); // only 10 bytes of payload

        let result = unwrap_websocket_frame(&frame);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("truncated"), "error: {err_msg}");
    }

    #[test]
    fn is_websocket_frame_rejects_too_short() {
        assert!(!is_websocket_frame(&[]));
        assert!(!is_websocket_frame(&[0x81]));
    }

    #[test]
    fn is_websocket_frame_rejects_control_frame() {
        // Close frame: opcode=8
        let frame = vec![0x88, 0x02, 0x03, 0xE8];
        assert!(!is_websocket_frame(&frame));
    }

    #[test]
    fn is_websocket_frame_rejects_rsv_bits_set() {
        // FIN=1, RSV1=1, opcode=1 — invalid
        let frame = vec![0xC1, 0x05, b'h', b'e', b'l', b'l', b'o'];
        assert!(!is_websocket_frame(&frame));
    }

    #[test]
    fn unwrap_binary_frame() {
        let payload = b"\x00\x01\x02\x03binary data";
        let mut frame = Vec::new();
        // FIN=1, RSV=0, opcode=2 (binary)
        frame.push(0x82);
        frame.push(payload.len() as u8);
        frame.extend_from_slice(payload);

        assert!(is_websocket_frame(&frame));
        let result = unwrap_websocket_frame(&frame).unwrap();
        assert_eq!(result, Some(payload.to_vec()));
    }
}
