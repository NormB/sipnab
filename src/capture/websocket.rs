// SPDX-License-Identifier: MIT OR Apache-2.0

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

/// WebSocket text-frame opcode ([RFC 6455 section 5.2](https://www.rfc-editor.org/rfc/rfc6455#section-5.2)).
const OPCODE_TEXT: u8 = 1;
/// WebSocket binary-frame opcode ([RFC 6455 section 5.2](https://www.rfc-editor.org/rfc/rfc6455#section-5.2)).
const OPCODE_BINARY: u8 = 2;

/// Ports where SIP-over-WebSocket traffic is expected when the operator has
/// declared nothing.
///
/// This is the BROWSER's view of the web, not a deployment's. Kamailio,
/// OpenSIPS and Janus each ship WSS on ports outside it, and behind a reverse
/// proxy the port sipnab sees is whichever one the proxy forwards to — so on
/// those deployments the entire WebRTC signaling leg used to be invisible,
/// with no skip report and nothing said. Replace the set with
/// `--ws-portrange` or `[capture] ws_ports`; see
/// [`crate::cli::Cli::ws_port_range`].
pub const WS_PORTS: &[u16] = &[80, 443, 8080, 8443];

/// The port range this process declared, packed as `lo << 16 | hi`.
///
/// `0` means "nothing declared", which is distinguishable from every real
/// range because clap and the config loader both refuse port 0. Process-global
/// and written once at startup, the same shape as
/// [`crate::rtp::stream::set_lost_seq_log_cap`] and for the same reason:
/// unwrapping happens on the batch path, the TUI path, every `--cores` shard
/// and the WASM entry point, and a value threaded to some of them is a setting
/// honored on some surfaces and ignored on others.
static WS_PORT_RANGE: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

/// Declare the SIP-over-WebSocket port range for this process. Call once, at
/// startup.
///
/// # Arguments
///
/// * `range` — the inclusive `(lo, hi)` an operator asked for, or `None` to
///   keep the shipped set.
///
/// # Side effects
///
/// Stores the packed range into a process-wide atomic (relaxed ordering).
pub fn set_ws_port_range(range: Option<(u16, u16)>) {
    let packed = range.map_or(0, |(lo, hi)| (u32::from(lo) << 16) | u32::from(hi));
    WS_PORT_RANGE.store(packed, std::sync::atomic::Ordering::Relaxed);
}

/// The declared range, or `None` when the shipped set is in force.
#[must_use]
pub fn ws_port_range() -> Option<(u16, u16)> {
    match WS_PORT_RANGE.load(std::sync::atomic::Ordering::Relaxed) {
        0 => None,
        packed => Some(((packed >> 16) as u16, packed as u16)),
    }
}

/// Whether `port` is one sipnab will unwrap SIP-over-WebSocket on.
///
/// A declared range REPLACES the shipped set rather than adding to it, exactly
/// as `--portrange` replaces the default signaling ports. The traffic that
/// falls outside is not silently dropped: `crate::pipeline::try_websocket_unwrap`
/// tallies it and `crate::pipeline::ws_port_skip_report` names the ports.
#[must_use]
pub fn is_ws_port(port: u16) -> bool {
    match ws_port_range() {
        Some((lo, hi)) => (lo..=hi).contains(&port),
        None => WS_PORTS.contains(&port),
    }
}

/// The port set in force, spelled the way an operator wrote it, for reports.
#[must_use]
pub fn ws_ports_description() -> String {
    match ws_port_range() {
        Some((lo, hi)) => format!("{lo}-{hi}"),
        None => WS_PORTS
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join(", "),
    }
}

/// WebSocket continuation-frame opcode ([RFC 6455 section 5.4](https://www.rfc-editor.org/rfc/rfc6455#section-5.4)).
const OPCODE_CONTINUATION: u8 = 0;

/// Most bytes one SIP message may take when a sender fragments it across
/// several WebSocket frames ([RFC 6455 section 5.4](https://www.rfc-editor.org/rfc/rfc6455#section-5.4)):
/// the same 64 KB as one frame's payload, `MAX_FRAME_SIZE`. A message that
/// outgrows it is counted NOT DECODED and dropped rather than held.
pub const MAX_WS_MESSAGE_SIZE: usize = 65_536;

/// One frame header, as [RFC 6455 section 5.2](https://www.rfc-editor.org/rfc/rfc6455#section-5.2) lays it out.
///
/// Layout only. Whether a FIN bit, reserved bit or opcode is acceptable is
/// each caller's policy, so the byte arithmetic lives here once and the
/// callers cannot disagree about where a frame ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FrameHeader {
    /// The FIN bit: this frame ends its message.
    pub(crate) fin: bool,
    /// The three reserved bits, still in place (`byte0 & 0x70`).
    pub(crate) rsv: u8,
    /// The opcode nibble.
    pub(crate) opcode: u8,
    /// The masking key, when the frame is masked.
    pub(crate) mask: Option<[u8; 4]>,
    /// Bytes of header, mask key included.
    pub(crate) header_len: usize,
    /// Bytes of payload the header declares.
    pub(crate) payload_len: usize,
}

/// Parse the frame header at the start of `data`.
///
/// # Returns
///
/// `Ok(None)` when `data` ends before the header does, which is not an error
/// on a stream: the rest arrives in the next chunk.
///
/// # Errors
///
/// The declared payload exceeds `MAX_FRAME_SIZE`, or its length is not
/// minimally encoded.
pub(crate) fn parse_frame_header(data: &[u8]) -> Result<Option<FrameHeader>> {
    let (Some(&byte0), Some(&byte1)) = (data.first(), data.get(1)) else {
        return Ok(None);
    };
    let masked = byte1 & 0x80 != 0;
    let len7 = u64::from(byte1 & 0x7F);
    let header_len = header_size(len7, masked);
    if data.len() < header_len {
        return Ok(None);
    }
    let payload_len = match len7 {
        126 => u64::from(u16::from_be_bytes([data[2], data[3]])),
        127 => u64::from_be_bytes([
            data[2], data[3], data[4], data[5], data[6], data[7], data[8], data[9],
        ]),
        n => n,
    };
    if payload_len > MAX_FRAME_SIZE {
        bail!("WebSocket frame payload too large ({payload_len} bytes, max {MAX_FRAME_SIZE})");
    }
    if length_encoding_is_not_minimal(len7, payload_len) {
        bail!(
            "WebSocket length {payload_len} is not minimally encoded: RFC 6455 \
             §5.2 requires the shortest form that can carry it"
        );
    }
    let mask = masked.then(|| {
        let k = header_len - 4;
        [data[k], data[k + 1], data[k + 2], data[k + 3]]
    });
    Ok(Some(FrameHeader {
        fin: byte0 & 0x80 != 0,
        rsv: byte0 & 0x70,
        opcode: byte0 & 0x0F,
        mask,
        header_len,
        // Bounded by MAX_FRAME_SIZE just above, so it fits every usize.
        payload_len: payload_len as usize,
    }))
}

/// `payload` unmasked with `mask` ([RFC 6455 section 5.3](https://www.rfc-editor.org/rfc/rfc6455#section-5.3)).
fn unmask(payload: &[u8], mask: Option<[u8; 4]>) -> Vec<u8> {
    match mask {
        Some(key) => payload
            .iter()
            .enumerate()
            .map(|(i, &b)| b ^ key[i % 4])
            .collect(),
        None => payload.to_vec(),
    }
}

/// Check if data looks like a WebSocket frame (heuristic).
///
/// Returns `true` if the first two bytes are consistent with a WebSocket
/// Whether `declared` is expressible in a shorter length form than `len7`
/// chose.
///
/// [RFC 6455 section 5.2](https://www.rfc-editor.org/rfc/rfc6455#section-5.2): *"the minimal number of bytes MUST be used to encode the
/// length, for example, the length of a 124-byte-long string can't be encoded
/// as the sequence 126, 0, 124."* The RFC gives the example because the
/// encoding is otherwise ambiguous, and an ambiguity a decoder accepts is
/// discrimination it has spent — on a detector whose whole job is telling a
/// frame from any other TCP payload starting with two plausible bytes.
///
/// One rule, one place: [`is_websocket_frame`] and [`unwrap_websocket_frame`]
/// both ask it, so a caller cannot be told a frame is valid and then handed a
/// refusal for it.
///
/// The 64-bit form's other rule — *"the most significant bit MUST be 0"* — is
/// not tested separately because `MAX_FRAME_SIZE` already subsumes it: any
/// value with that bit set is at least 2^63 and is refused as oversized. A
/// check here would be unreachable, and an unreachable check is one nobody can
/// show works.
fn length_encoding_is_not_minimal(len7: u64, declared: u64) -> bool {
    match len7 {
        126 => declared < 126,
        127 => declared <= u64::from(u16::MAX),
        _ => false,
    }
}

/// data frame: FIN bit set, reserved bits zero, opcode 1 (text) or 2
/// (binary), and enough remaining bytes for the declared payload length.
pub fn is_websocket_frame(data: &[u8]) -> bool {
    match parse_frame_header(data) {
        Ok(Some(h)) => {
            h.fin
                && h.rsv == 0
                && (h.opcode == OPCODE_TEXT || h.opcode == OPCODE_BINARY)
                && data.len() >= h.header_len + h.payload_len
        }
        _ => false,
    }
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
    let opcode = data[0] & 0x0F;
    // Control frames (close, ping, pong) and anything that is not a text or
    // binary data frame carry no SIP message.
    if opcode != OPCODE_TEXT && opcode != OPCODE_BINARY {
        return Ok(None);
    }
    let Some(h) = parse_frame_header(data)? else {
        bail!(
            "WebSocket frame truncated: need {} header bytes, have {}",
            header_size(u64::from(data[1] & 0x7F), data[1] & 0x80 != 0),
            data.len()
        );
    };
    let end = h.header_len + h.payload_len;
    if data.len() < end {
        bail!(
            "WebSocket frame truncated: need {end} bytes total, have {}",
            data.len()
        );
    }
    Ok(Some(unmask(&data[h.header_len..end], h.mask)))
}

/// Joins the WebSocket frames of one direction of a stream across the chunks
/// they arrive in, and the frames of one message across its fragments.
///
/// A sender may write one frame as several chunks: OpenSIPS writes each
/// frame's 4-byte header in one TLS record and its payload in the next. It may
/// write several frames in one chunk, and it may fragment one message across
/// several frames ([RFC 6455 section 5.4](https://www.rfc-editor.org/rfc/rfc6455#section-5.4)).
/// Reading each chunk as one whole frame lost everything OpenSIPS sent over
/// WSS (found reproducing issue #301).
///
/// Bounded: a frame is refused by `parse_frame_header` past `MAX_FRAME_SIZE`,
/// so the held bytes never exceed one frame, and a fragmented message past
/// [`MAX_WS_MESSAGE_SIZE`] is refused. Every refusal is returned to be counted.
#[derive(Debug, Default)]
pub struct WsStream {
    /// Bytes of a frame not complete yet.
    buf: Vec<u8>,
    /// The payload so far of a message fragmented across frames.
    message: Vec<u8>,
    /// Whether a fragmented message is open, awaiting continuation frames.
    in_message: bool,
}

/// What one chunk of a WebSocket stream yielded.
#[derive(Debug, Default)]
pub struct WsOutput {
    /// Each complete message's payload, unmasked, in stream order.
    pub messages: Vec<Vec<u8>>,
    /// Why a frame or message could not be decoded, one entry each. The
    /// stream is resynchronized at the next chunk.
    pub refused: Vec<String>,
}

impl WsStream {
    /// Feed the next chunk of this direction's bytes.
    pub fn push(&mut self, chunk: &[u8]) -> WsOutput {
        let mut out = WsOutput::default();
        self.buf.extend_from_slice(chunk);
        loop {
            let h = match parse_frame_header(&self.buf) {
                Ok(Some(h)) => h,
                Ok(None) => break,
                Err(e) => {
                    out.refused.push(e.to_string());
                    self.reset();
                    break;
                }
            };
            let end = h.header_len + h.payload_len;
            if self.buf.len() < end {
                break;
            }
            let payload = unmask(&self.buf[h.header_len..end], h.mask);
            self.buf.drain(..end);
            if let Err(why) = self.take_frame(&h, payload, &mut out.messages) {
                out.refused.push(why);
                self.reset();
                break;
            }
        }
        out
    }

    /// Apply one complete frame to the message being assembled.
    ///
    /// # Errors
    ///
    /// The frame breaks [RFC 6455 section 5](https://www.rfc-editor.org/rfc/rfc6455#section-5):
    /// reserved bits with no extension negotiated, an unknown opcode, a
    /// fragmented control frame, a continuation with no message open or a new
    /// message inside an open one, or a message past [`MAX_WS_MESSAGE_SIZE`].
    fn take_frame(
        &mut self,
        h: &FrameHeader,
        payload: Vec<u8>,
        messages: &mut Vec<Vec<u8>>,
    ) -> std::result::Result<(), String> {
        if h.rsv != 0 {
            return Err("WebSocket frame sets reserved bits".to_string());
        }
        match h.opcode {
            // Close, ping, pong: may sit between fragments, carry no message.
            8..=10 if h.fin => Ok(()),
            8..=10 => Err("WebSocket control frame is fragmented".to_string()),
            OPCODE_TEXT | OPCODE_BINARY if self.in_message => {
                Err("WebSocket data frame inside an unfinished message".to_string())
            }
            OPCODE_TEXT | OPCODE_BINARY if h.fin => {
                messages.push(payload);
                Ok(())
            }
            OPCODE_TEXT | OPCODE_BINARY => {
                self.message = payload;
                self.in_message = true;
                Ok(())
            }
            OPCODE_CONTINUATION if !self.in_message => {
                Err("WebSocket continuation frame with no message open".to_string())
            }
            OPCODE_CONTINUATION => {
                if self.message.len() + payload.len() > MAX_WS_MESSAGE_SIZE {
                    return Err(format!(
                        "WebSocket message exceeds MAX_WS_MESSAGE_SIZE ({MAX_WS_MESSAGE_SIZE} bytes)"
                    ));
                }
                self.message.extend_from_slice(&payload);
                if h.fin {
                    messages.push(std::mem::take(&mut self.message));
                    self.in_message = false;
                }
                Ok(())
            }
            other => Err(format!("WebSocket frame has reserved opcode {other}")),
        }
    }

    /// Bytes held for a frame or message not complete yet.
    pub fn pending(&self) -> usize {
        self.buf.len() + self.message.len()
    }

    /// What an abandoned stream still holds, as `(need, got)`: the bytes the
    /// frame in progress declares, when its header is complete, and the bytes
    /// held. `None` when nothing is held.
    pub fn held(&self) -> Option<(usize, usize)> {
        let got = self.pending();
        if got == 0 {
            return None;
        }
        let need = match parse_frame_header(&self.buf) {
            Ok(Some(h)) => self.message.len() + h.header_len + h.payload_len,
            _ => got + 1,
        };
        Some((need, got))
    }

    /// Drop what is held, to resynchronize after a refusal.
    fn reset(&mut self) {
        self.buf.clear();
        self.message.clear();
        self.in_message = false;
    }
}

/// Whether decrypted bytes begin a WebSocket session or frame stream rather
/// than SIP: the HTTP upgrade request, the `101 Switching Protocols` answer,
/// or bytes shaped like the start of a data frame.
///
/// The frame test cannot mistake SIP text: every ASCII letter and digit has
/// a bit in `0x70` set, which a frame must leave clear, so a SIP start line or
/// a SIP body continuation never reads as a frame.
pub fn starts_websocket(data: &[u8]) -> bool {
    if data.starts_with(b"HTTP/1.1 101") {
        return true;
    }
    if data.starts_with(b"GET ") {
        let head = &data[..data.len().min(2048)];
        return head
            .windows(9)
            .any(|w| w.eq_ignore_ascii_case(b"websocket"));
    }
    matches!(
        parse_frame_header(data),
        Ok(Some(h)) if h.rsv == 0 && (h.opcode == OPCODE_TEXT || h.opcode == OPCODE_BINARY)
    )
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

/// Unit tests for WebSocket frame detection and unwrapping, covering masked and
/// unmasked frames, extended-length encodings, control frames, and truncation
/// / oversize error paths.
#[cfg(test)]
mod tests {
    use super::*;

    /// A frame with an explicit FIN bit and opcode, unmasked.
    fn frame(fin: bool, opcode: u8, payload: &[u8]) -> Vec<u8> {
        let mut f = vec![if fin { 0x80 } else { 0 } | opcode];
        match payload.len() {
            n if n < 126 => f.push(n as u8),
            n => {
                f.push(126);
                f.extend_from_slice(&(n as u16).to_be_bytes());
            }
        }
        f.extend_from_slice(payload);
        f
    }

    /// A fragmented message past `MAX_WS_MESSAGE_SIZE` is refused and the
    /// stream holds nothing afterwards: the bound is a refusal to count,
    /// never an unbounded buffer.
    #[test]
    fn a_stream_refuses_a_message_past_its_ceiling() {
        let mut ws = WsStream::default();
        let big = vec![b'a'; 60_000];
        let out = ws.push(&frame(false, OPCODE_TEXT, &big));
        assert!(out.messages.is_empty() && out.refused.is_empty());
        assert_eq!(ws.pending(), 60_000, "the open message is held");
        let out = ws.push(&frame(true, OPCODE_CONTINUATION, &vec![b'b'; 10_000]));
        assert!(out.messages.is_empty());
        assert_eq!(out.refused.len(), 1, "{:?}", out.refused);
        assert!(
            out.refused[0].contains("MAX_WS_MESSAGE_SIZE"),
            "{:?}",
            out.refused
        );
        assert_eq!(ws.pending(), 0);
    }

    /// Frames that break [RFC 6455 section 5](https://www.rfc-editor.org/rfc/rfc6455#section-5) are refused one by one, and the
    /// stream decodes the next good frame after each.
    #[test]
    fn a_stream_refuses_frames_that_break_the_protocol_and_recovers() {
        for (bad, why) in [
            (frame(true, OPCODE_CONTINUATION, b"x"), "continuation"),
            (frame(true, 3, b"x"), "reserved opcode"),
            (frame(false, 9, b"x"), "fragmented"),
            (vec![0xC1, 1, b'x'], "reserved bits"),
        ] {
            let mut ws = WsStream::default();
            let out = ws.push(&bad);
            assert_eq!(out.refused.len(), 1, "{why}: {:?}", out.refused);
            assert!(out.refused[0].contains(why), "{why}: {:?}", out.refused);
            let out = ws.push(&frame(true, OPCODE_TEXT, b"next"));
            assert_eq!(out.messages, vec![b"next".to_vec()], "{why}");
        }
    }

    /// A control frame between two fragments does not end the message.
    #[test]
    fn a_control_frame_between_fragments_is_skipped() {
        let mut ws = WsStream::default();
        let mut chunk = frame(false, OPCODE_TEXT, b"INV");
        chunk.extend_from_slice(&frame(true, 9, b"ping"));
        chunk.extend_from_slice(&frame(true, OPCODE_CONTINUATION, b"ITE"));
        let out = ws.push(&chunk);
        assert_eq!(out.messages, vec![b"INVITE".to_vec()]);
        assert!(out.refused.is_empty());
    }

    /// What an abandoned stream held is reported as need and got.
    #[test]
    fn held_reports_what_an_unfinished_frame_needed() {
        let mut ws = WsStream::default();
        assert_eq!(ws.held(), None);
        let f = frame(true, OPCODE_TEXT, &[b'z'; 200]);
        ws.push(&f[..4]);
        assert_eq!(ws.held(), Some((f.len(), 4)));
    }

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

    /// A frame in the extended form that a shorter form could have carried.
    ///
    /// `len7` chooses the encoding; `declared` is what the extension bytes
    /// claim. A conformant sender never produces a pair a shorter form could
    /// have expressed.
    fn frame_with_declared_len(len7: u8, declared: u64, payload: &[u8]) -> Vec<u8> {
        let mut frame = vec![0x81, len7];
        match len7 {
            126 => frame.extend_from_slice(&u16::try_from(declared).unwrap_or(0).to_be_bytes()),
            127 => frame.extend_from_slice(&declared.to_be_bytes()),
            _ => {}
        }
        frame.extend_from_slice(payload);
        frame
    }

    /// [RFC 6455 section 5.2](https://www.rfc-editor.org/rfc/rfc6455#section-5.2): *"the minimal number of bytes MUST be used to
    /// encode the length, for example, the length of a 124-byte-long string
    /// can't be encoded as the sequence 126, 0, 124."*
    ///
    /// The RFC gives the example because the encoding is otherwise ambiguous,
    /// and an ambiguity a decoder accepts is discrimination it has spent. This
    /// one is worth 126 values of the 16-bit space, on a detector whose whole
    /// job is telling a WebSocket frame from any other TCP payload that
    /// happens to start with two plausible bytes.
    #[test]
    fn a_two_byte_length_that_a_seven_bit_field_could_carry_is_not_a_frame() {
        for declared in [0u64, 1, 100, 124, 125] {
            let payload = vec![b'x'; usize::try_from(declared).unwrap_or(0)];
            let frame = frame_with_declared_len(126, declared, &payload);
            assert!(
                !is_websocket_frame(&frame),
                "length {declared} fits the 7-bit field, so the 126 form is \
                 non-conformant and must not read as a frame"
            );
        }
    }

    /// And the first length that genuinely needs the two-byte form does.
    ///
    /// The positive control. A rule written one off — rejecting 126 itself —
    /// would refuse every frame between 126 and 65535 bytes, which is most
    /// SIP over WebSocket, while every assertion above still passed.
    #[test]
    fn the_smallest_length_that_needs_two_bytes_is_a_frame() {
        let payload = vec![b'x'; 126];
        let frame = frame_with_declared_len(126, 126, &payload);
        assert!(
            is_websocket_frame(&frame),
            "126 cannot be expressed in the 7-bit field and is the minimal encoding"
        );
    }

    /// The same rule one form up: eight bytes for a length two would carry.
    #[test]
    fn an_eight_byte_length_that_two_bytes_could_carry_is_not_a_frame() {
        // The payload is built to the DECLARED length, every time. Capping it
        // made the 0xFFFF case pass for the wrong reason: the frame was short
        // of what it declared, so the detector rejected it as truncated and
        // never reached the encoding rule. Mutation found that — moving the
        // comparison off the boundary changed nothing.
        for declared in [0u64, 125, 126, 1000, 0xFFFF] {
            let payload = vec![b'x'; usize::try_from(declared).unwrap_or(0)];
            let frame = frame_with_declared_len(127, declared, &payload);
            assert!(
                !is_websocket_frame(&frame),
                "length {declared} fits the two-byte form, so the 127 form is \
                 non-conformant"
            );
        }
    }

    /// And the first length that genuinely needs eight bytes does.
    ///
    /// One value reaches it here, because `MAX_FRAME_SIZE` is 65536 and every
    /// smaller length must use the two-byte form. That the window is one value
    /// wide is the reason to test it: a rule written `>=` instead of `>` would
    /// close it entirely and nothing else would notice.
    #[test]
    fn the_smallest_length_that_needs_eight_bytes_is_a_frame() {
        let declared = 0x1_0000u64;
        let payload = vec![b'x'; 0x1_0000];
        let frame = frame_with_declared_len(127, declared, &payload);
        assert!(
            is_websocket_frame(&frame),
            "65536 cannot be expressed in two bytes and is within MAX_FRAME_SIZE"
        );
    }

    /// The detector and the unwrapper read the same rule.
    ///
    /// Two answers about one frame is the defect this pairing exists to stop:
    /// a caller that trusts the detector and then unwraps would otherwise get
    /// a payload out of a frame the detector had refused, or a refusal for one
    /// it had accepted.
    #[test]
    fn the_unwrapper_refuses_exactly_what_the_detector_refuses() {
        for (len7, declared) in [(126u8, 10u64), (126, 125), (127, 0xFFFF), (127, 0)] {
            // Full-length payloads, for the reason the test above records: a
            // short frame is refused as truncated and proves nothing about
            // the rule under test.
            let payload = vec![b'x'; usize::try_from(declared).unwrap_or(0)];
            let frame = frame_with_declared_len(len7, declared, &payload);
            assert!(!is_websocket_frame(&frame), "{len7}/{declared}");
            assert!(
                unwrap_websocket_frame(&frame).is_err(),
                "the detector refused {len7}/{declared} and the unwrapper did not"
            );
        }
    }

    /// A length inside the 7-bit field is untouched by any of this.
    ///
    /// The regression control: the rule applies to the extended forms only,
    /// and a version of it that reached the 7-bit field would reject every
    /// ordinary short frame — which is most SIP signaling.
    #[test]
    fn a_seven_bit_length_is_unaffected() {
        for len in [0usize, 1, 60, 125] {
            let payload = vec![b'x'; len];
            let frame = build_unmasked_text_frame(&payload);
            assert!(is_websocket_frame(&frame), "a {len}-byte frame must parse");
        }
    }

    /// An unmasked text frame is detected and unwraps to its exact payload.
    #[test]
    fn unwrap_unmasked_text_frame() {
        let payload = b"INVITE sip:bob@example.com SIP/2.0\r\n\r\n";
        let frame = build_unmasked_text_frame(payload);

        assert!(is_websocket_frame(&frame));
        let result = unwrap_websocket_frame(&frame).unwrap();
        assert_eq!(result, Some(payload.to_vec()));
    }

    /// A masked frame is detected and XOR-unmasks back to the original payload.
    #[test]
    fn unwrap_masked_frame() {
        let payload = b"SIP/2.0 200 OK\r\n\r\n";
        let mask_key = [0x37, 0xFA, 0x21, 0x3D];
        let frame = build_masked_text_frame(payload, mask_key);

        assert!(is_websocket_frame(&frame));
        let result = unwrap_websocket_frame(&frame).unwrap();
        assert_eq!(result, Some(payload.to_vec()));
    }

    /// A payload > 125 bytes uses the 126-format 16-bit length and unwraps
    /// correctly.
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

    /// A close control frame (opcode 8) unwraps to `None`, not an error.
    #[test]
    fn control_frame_close_returns_none() {
        // opcode 8 = close, FIN=1
        let frame = vec![0x88, 0x02, 0x03, 0xE8]; // close with status 1000

        let result = unwrap_websocket_frame(&frame).unwrap();
        assert!(result.is_none());
    }

    /// A frame declaring a payload above the 64 KB limit errors with "too large".
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

    /// A header declaring more payload than is present errors with "truncated".
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

    /// Inputs shorter than the 2-byte minimum header are not WebSocket frames.
    #[test]
    fn is_websocket_frame_rejects_too_short() {
        assert!(!is_websocket_frame(&[]));
        assert!(!is_websocket_frame(&[0x81]));
    }

    /// A control frame (opcode 8) fails the data-frame detection heuristic.
    #[test]
    fn is_websocket_frame_rejects_control_frame() {
        // Close frame: opcode=8
        let frame = vec![0x88, 0x02, 0x03, 0xE8];
        assert!(!is_websocket_frame(&frame));
    }

    /// A frame with an RSV bit set is rejected by the detection heuristic.
    #[test]
    fn is_websocket_frame_rejects_rsv_bits_set() {
        // FIN=1, RSV1=1, opcode=1 — invalid
        let frame = vec![0xC1, 0x05, b'h', b'e', b'l', b'l', b'o'];
        assert!(!is_websocket_frame(&frame));
    }

    /// A binary frame (opcode 2) is detected and unwraps to its payload.
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
