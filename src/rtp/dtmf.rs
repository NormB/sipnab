// SPDX-License-Identifier: MIT OR Apache-2.0

//! RFC 4733 telephone-event (DTMF) extraction.
//!
//! Decodes DTMF digits carried as RTP telephone-event payloads rather
//! than in-band audio tones. The telephone-event format uses a dedicated
//! RTP payload type (negotiated via SDP) and carries a 4-byte event
//! descriptor per packet.
//!
//! Only events with the End bit set are returned, which deduplicates the
//! intermediate packets that RTP senders transmit for reliability.

use chrono::{DateTime, Utc};

// ── Public types ─────────────────────────────────────────────────────

/// A decoded DTMF event from an RFC 4733 telephone-event RTP packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DtmfEvent {
    /// The DTMF digit: `'0'`-`'9'`, `'*'`, `'#'`, or `'A'`-`'D'`.
    pub digit: char,
    /// Event duration in milliseconds (derived from the RTP timestamp units).
    pub duration_ms: u32,
    /// Capture timestamp of the packet.
    pub timestamp: DateTime<Utc>,
}

// ── Public API ───────────────────────────────────────────────────────

/// Extract a DTMF event from an RTP telephone-event payload.
///
/// RFC 4733 telephone-event format (4 bytes):
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     event     |E|R| volume    |          duration             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// - `event`: 0-9 = digits, 10 = `*`, 11 = `#`, 12-15 = A-D
/// - `E` bit: 1 = end of event (only these are returned)
/// - `duration`: in RTP timestamp units of the telephone-event clock
///
/// This is a convenience wrapper over [`extract_dtmf_with_clock`] that
/// assumes the RFC 4733 default 8000 Hz telephone-event clock. Callers that
/// know the negotiated clock rate — e.g. a `16000` Hz wideband
/// telephone-event from `a=rtpmap:<pt> telephone-event/16000` — should call
/// [`extract_dtmf_with_clock`] directly so the reported duration is correct.
///
/// # Arguments
///
/// * `payload` — the RTP payload bytes (after the RTP header).
/// * `payload_type` — the PT from the RTP header for this packet.
/// * `expected_pt` — the telephone-event PT negotiated via SDP.
/// * `timestamp` — capture timestamp for the resulting event.
///
/// # Returns
///
/// `Some(DtmfEvent)` if this is a complete telephone-event (E bit set)
/// with a valid digit. `None` for intermediate packets, wrong payload
/// type, or payloads too short to decode.
pub fn extract_dtmf(
    payload: &[u8],
    payload_type: u8,
    expected_pt: u8,
    timestamp: DateTime<Utc>,
) -> Option<DtmfEvent> {
    extract_dtmf_with_clock(payload, payload_type, expected_pt, 8000, timestamp)
}

/// Extract a DTMF event using an explicit telephone-event clock rate.
///
/// The RFC 4733 `duration` field is expressed in RTP timestamp units of the
/// telephone-event clock, which is negotiated in SDP as
/// `a=rtpmap:<pt> telephone-event/<clock_rate>`. It is commonly 8000 Hz but
/// is 16000 Hz for wideband; assuming 8000 Hz for a 16 kHz event reports
/// double the true duration. Pass the negotiated `clock_rate` (in Hz) so the
/// duration is scaled correctly.
///
/// # Arguments
///
/// * `payload` — the RTP payload bytes (after the RTP header).
/// * `payload_type` — the PT from the RTP header for this packet.
/// * `expected_pt` — the telephone-event PT negotiated via SDP.
/// * `clock_rate` — the telephone-event clock rate in Hz (from the SDP
///   rtpmap for `expected_pt`).
/// * `timestamp` — capture timestamp for the resulting event.
///
/// # Returns
///
/// `Some(DtmfEvent)` if this is a complete telephone-event (E bit set)
/// with a valid digit. `None` for intermediate packets, wrong payload
/// type, payloads too short to decode, or a zero `clock_rate`.
pub fn extract_dtmf_with_clock(
    payload: &[u8],
    payload_type: u8,
    expected_pt: u8,
    clock_rate: u32,
    timestamp: DateTime<Utc>,
) -> Option<DtmfEvent> {
    // Only process if the payload type matches the negotiated telephone-event PT
    if payload_type != expected_pt {
        return None;
    }

    // A zero clock rate would divide by zero; a valid rtpmap never carries one.
    if clock_rate == 0 {
        return None;
    }

    // Minimum 4 bytes for the telephone-event descriptor
    if payload.len() < 4 {
        return None;
    }

    let event = payload[0];
    let e_bit = (payload[1] >> 7) & 0x01;

    // Only return completed events (E bit = 1) to avoid duplicates
    if e_bit != 1 {
        return None;
    }

    let duration_ts = u16::from_be_bytes([payload[2], payload[3]]);
    // Convert from RTP timestamp units to milliseconds using the negotiated
    // clock rate: ms = ts_units * 1000 / clock_rate.
    let duration_ms = (duration_ts as u64 * 1000 / clock_rate as u64) as u32;

    let digit = event_to_digit(event)?;

    Some(DtmfEvent {
        digit,
        duration_ms,
        timestamp,
    })
}

/// Map an RFC 4733 event code to its DTMF character.
///
/// Returns `None` for event codes outside the DTMF range (0-15).
fn event_to_digit(event: u8) -> Option<char> {
    match event {
        0 => Some('0'),
        1 => Some('1'),
        2 => Some('2'),
        3 => Some('3'),
        4 => Some('4'),
        5 => Some('5'),
        6 => Some('6'),
        7 => Some('7'),
        8 => Some('8'),
        9 => Some('9'),
        10 => Some('*'),
        11 => Some('#'),
        12 => Some('A'),
        13 => Some('B'),
        14 => Some('C'),
        15 => Some('D'),
        _ => None,
    }
}

// ── Tests ────────────────────────────────────────────────────────────

/// Unit tests for RFC 4733 telephone-event (DTMF) extraction.
#[cfg(test)]
mod tests {
    use super::*;

    /// A fixed capture timestamp for the extracted events.
    fn ts() -> DateTime<Utc> {
        DateTime::from_timestamp(1_700_000_000, 0).expect("valid timestamp")
    }

    /// Build a telephone-event payload.
    fn build_event(event: u8, end: bool, volume: u8, duration: u16) -> Vec<u8> {
        let byte1 = if end { 0x80 } else { 0x00 } | (volume & 0x3F);
        vec![event, byte1, (duration >> 8) as u8, (duration & 0xFF) as u8]
    }

    /// Digit 1 with the End bit is extracted with its duration in ms.
    #[test]
    fn extract_digit_1_end() {
        let payload = build_event(1, true, 10, 1600); // 200ms at 8kHz
        let event = extract_dtmf(&payload, 101, 101, ts());
        let event = event.expect("should extract digit 1");
        assert_eq!(event.digit, '1');
        assert_eq!(event.duration_ms, 200);
    }

    /// Digit 0 is extracted with the correct duration.
    #[test]
    fn extract_digit_0() {
        let payload = build_event(0, true, 10, 800);
        let event = extract_dtmf(&payload, 101, 101, ts()).expect("should extract digit 0");
        assert_eq!(event.digit, '0');
        assert_eq!(event.duration_ms, 100);
    }

    /// Event code 10 maps to the `*` digit.
    #[test]
    fn extract_star() {
        let payload = build_event(10, true, 10, 1600);
        let event = extract_dtmf(&payload, 101, 101, ts()).expect("should extract *");
        assert_eq!(event.digit, '*');
    }

    /// Event code 11 maps to the `#` digit.
    #[test]
    fn extract_hash() {
        let payload = build_event(11, true, 10, 1600);
        let event = extract_dtmf(&payload, 101, 101, ts()).expect("should extract #");
        assert_eq!(event.digit, '#');
    }

    /// Event code 12 maps to the `A` digit.
    #[test]
    fn extract_letter_a() {
        let payload = build_event(12, true, 10, 1600);
        let event = extract_dtmf(&payload, 101, 101, ts()).expect("should extract A");
        assert_eq!(event.digit, 'A');
    }

    /// Event code 15 maps to the `D` digit.
    #[test]
    fn extract_letter_d() {
        let payload = build_event(15, true, 10, 1600);
        let event = extract_dtmf(&payload, 101, 101, ts()).expect("should extract D");
        assert_eq!(event.digit, 'D');
    }

    /// Intermediate packets (End bit clear) return `None`.
    #[test]
    fn intermediate_packet_not_returned() {
        // E bit = 0 (intermediate)
        let payload = build_event(5, false, 10, 800);
        let event = extract_dtmf(&payload, 101, 101, ts());
        assert!(event.is_none(), "Intermediate packets should return None");
    }

    /// A payload type not matching the negotiated PT returns `None`.
    #[test]
    fn wrong_payload_type_not_returned() {
        let payload = build_event(1, true, 10, 1600);
        // PT 96 doesn't match expected 101
        let event = extract_dtmf(&payload, 96, 101, ts());
        assert!(event.is_none(), "Wrong PT should return None");
    }

    /// A payload under 4 bytes is too short to decode and returns `None`.
    #[test]
    fn payload_too_short() {
        let event = extract_dtmf(&[0x01, 0x80], 101, 101, ts());
        assert!(event.is_none(), "Payload < 4 bytes should return None");
    }

    /// An empty payload returns `None`.
    #[test]
    fn empty_payload() {
        let event = extract_dtmf(&[], 101, 101, ts());
        assert!(event.is_none(), "Empty payload should return None");
    }

    /// An event code outside the DTMF range (16) returns `None`.
    #[test]
    fn invalid_event_code() {
        // Event 16 is outside DTMF range
        let payload = build_event(16, true, 10, 1600);
        let event = extract_dtmf(&payload, 101, 101, ts());
        assert!(event.is_none(), "Event code 16 should return None");
    }

    /// Every valid event code (0-15) maps to its expected DTMF character.
    #[test]
    fn all_digits_roundtrip() {
        let expected = [
            (0, '0'),
            (1, '1'),
            (2, '2'),
            (3, '3'),
            (4, '4'),
            (5, '5'),
            (6, '6'),
            (7, '7'),
            (8, '8'),
            (9, '9'),
            (10, '*'),
            (11, '#'),
            (12, 'A'),
            (13, 'B'),
            (14, 'C'),
            (15, 'D'),
        ];
        for (code, digit) in expected {
            let payload = build_event(code, true, 10, 1600);
            let event = extract_dtmf(&payload, 101, 101, ts())
                .unwrap_or_else(|| panic!("Should extract event code {code}"));
            assert_eq!(
                event.digit, digit,
                "Event code {code} should map to '{digit}'"
            );
        }
    }

    /// Duration in timestamp units is converted to ms assuming an 8 kHz clock.
    #[test]
    fn duration_calculation() {
        // 3200 timestamp units at 8kHz = 400ms
        let payload = build_event(5, true, 10, 3200);
        let event = extract_dtmf(&payload, 101, 101, ts()).expect("should extract");
        assert_eq!(event.duration_ms, 400);
    }

    /// A 16 kHz telephone-event yields the correct duration when the
    /// negotiated clock rate is supplied, rather than the doubled value the
    /// 8 kHz assumption produces.
    #[test]
    fn extract_dtmf_16khz_clock_correct_duration() {
        // 3200 timestamp units at 16 kHz = 200 ms (the 8 kHz assumption
        // would report 400 ms).
        let payload = build_event(1, true, 10, 3200);
        let event = extract_dtmf_with_clock(&payload, 101, 101, 16_000, ts())
            .expect("should extract digit 1");
        assert_eq!(event.digit, '1');
        assert_eq!(event.duration_ms, 200);
    }

    /// The 8 kHz-default `extract_dtmf` remains equivalent to calling
    /// `extract_dtmf_with_clock` with an 8000 Hz clock.
    #[test]
    fn extract_dtmf_defaults_to_8khz() {
        let payload = build_event(1, true, 10, 1600); // 200 ms at 8 kHz
        let default = extract_dtmf(&payload, 101, 101, ts());
        let explicit = extract_dtmf_with_clock(&payload, 101, 101, 8000, ts());
        assert_eq!(default, explicit);
        assert_eq!(default.expect("extract").duration_ms, 200);
    }
}
