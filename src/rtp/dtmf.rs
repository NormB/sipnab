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
//!
//! # Disclosure
//!
//! A decoded digit is not a diagnostic detail, it is the secret itself. On live
//! traffic the digit stream after answer is the PIN, the calling-card number,
//! the account number or the credit-card number the caller keyed in, and it
//! arrives in the clear regardless of how the signaling was protected. So this
//! module hands out [`MASKED_DIGIT`] as the value any always-on surface may
//! print, and reserves [`DtmfEvent::digit`] itself for a caller that has an
//! explicit operator opt-in (`--dtmf-cleartext`) to disclose it.

use chrono::{DateTime, Utc};

// ── Public constants ─────────────────────────────────────────────────

/// The placeholder that stands in for a decoded digit on any surface that
/// has not been explicitly opted in to cleartext disclosure.
///
/// Lowercase `x` is deliberate. The RFC 4733 alphabet is `0`-`9`, `*`, `#` and
/// `A`-`D`, so `x` cannot be read back as a keypress that actually happened —
/// which rules out the otherwise-obvious `*`, the star key, whose mask would be
/// indistinguishable from a caller who really pressed it. A masked line still
/// carries every fact an operator needs (that a digit arrived, when, for how
/// long, on which SSRC); only the value is withheld.
pub const MASKED_DIGIT: char = 'x';

// ── Public types ─────────────────────────────────────────────────────

/// A decoded DTMF event from an RFC 4733 telephone-event RTP packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DtmfEvent {
    /// The DTMF digit: `'0'`-`'9'`, `'*'`, `'#'`, or `'A'`-`'D'`.
    ///
    /// Treat this as a credential, not as a field. Anything that prints it
    /// without an explicit operator opt-in publishes the caller's PIN or card
    /// number to every reader of that surface; print [`MASKED_DIGIT`] instead.
    pub digit: char,
    /// Event duration in milliseconds (derived from the RTP timestamp units).
    pub duration_ms: u32,
    /// Capture timestamp of the packet.
    pub timestamp: DateTime<Utc>,
}

/// Remembers which telephone-event end packets have already been reported.
///
/// # Why this is needed
///
/// RFC 4733 §2.5.1.4 requires a sender to transmit the final packet of an
/// event **three times**, and to keep the E bit set on every one of them. A
/// reader that reports an event per E-bit packet therefore counts one keypress
/// three times — which it did, visibly, on every capture carrying DTMF.
///
/// # Why this key
///
/// The RFC guarantees the retransmissions are identical in the three fields
/// that matter: same SSRC, same RTP timestamp (the event's START, which does
/// not advance across the retransmissions), same event code. Nothing else
/// distinguishes them, and nothing else is needed.
///
/// # Bounded on purpose
///
/// The key is capture-derived, so an unbounded set is a growth path a sender
/// controls. Forgetting the oldest key can only re-report a keypress far in
/// the past, which is the harmless direction of the trade.
#[derive(Debug, Default)]
pub struct DtmfDedupe {
    /// Recent keys, oldest first.
    seen: std::collections::VecDeque<(u32, u32, u8)>,
}

impl DtmfDedupe {
    /// How many recent end-events are remembered.
    ///
    /// A keypress is three packets, so this holds well over a hundred distinct
    /// digits — far more than any real dialing sequence — while staying a
    /// fixed, tiny cost.
    pub const CAPACITY: usize = 512;

    /// Whether this end packet has already been reported.
    ///
    /// # Arguments
    ///
    /// * `ssrc` — the stream's synchronization source.
    /// * `rtp_timestamp` — the packet's RTP timestamp, which for a
    ///   telephone-event is the event's start and is identical across the
    ///   RFC 4733 §2.5.1.4 retransmissions.
    /// * `event` — the event code from the payload's first octet.
    ///
    /// # Returns
    ///
    /// `true` when this exact end packet was seen before, and the caller
    /// should not count it again.
    pub fn is_duplicate(&mut self, ssrc: u32, rtp_timestamp: u32, event: u8) -> bool {
        let key = (ssrc, rtp_timestamp, event);
        if self.seen.contains(&key) {
            return true;
        }
        if self.seen.len() >= Self::CAPACITY {
            self.seen.pop_front();
        }
        self.seen.push_back(key);
        false
    }

    /// How many keys are remembered. Test and diagnostic use.
    #[must_use]
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    /// Whether nothing has been seen yet.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

// ── Public API ───────────────────────────────────────────────────────

/// Extract a DTMF event from an RTP telephone-event payload, using the
/// negotiated telephone-event clock rate.
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
/// The `duration` field is expressed in RTP timestamp units of the
/// telephone-event clock, which is negotiated in SDP as
/// `a=rtpmap:<pt> telephone-event/<clock_rate>`. It is commonly 8000 Hz but
/// is 16000 Hz for wideband; assuming 8000 Hz for a 16 kHz event reports
/// double the true duration. Pass the negotiated `clock_rate` (in Hz) so the
/// duration is scaled correctly.
///
/// The clock rate is deliberately a required argument and there is no
/// 8 kHz-defaulting wrapper beside it. One existed, and it was the same shape
/// as `estimate_mos`'s: a convenience overload that bakes an assumption in, so
/// that a caller reaching for the shorter name silently gets the wideband
/// answer wrong. Callers with no SDP to read supply the RFC 4733 convention
/// themselves, at the call site, where it is visible.
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
    /// One keypress reports one event, not three.
    ///
    /// RFC 4733 §2.5.1.4: "The final packet for each event and for each
    /// segment SHOULD be sent a total of three times at the interval used by
    /// the source for updates", and "Once the sender has set the E bit for a
    /// packet, it MUST continue to set the E bit for any further
    /// retransmissions of that packet." So a conformant sender emits three
    /// E=1 packets per keypress and sipnab counted a digit for each.
    ///
    /// The retransmissions carry the SAME SSRC, the same RTP timestamp (the
    /// event's start) and the same event code — the RFC guarantees it, which
    /// is what makes those three a usable key.
    #[test]
    fn a_retransmitted_end_packet_is_not_a_second_keypress() {
        let mut seen = DtmfDedupe::default();
        // Digit 7, E=1, 2400 timestamp units — sent three times per §2.5.1.4.
        assert!(!seen.is_duplicate(0xCAFE_BABE, 160_000, 7));
        assert!(seen.is_duplicate(0xCAFE_BABE, 160_000, 7));
        assert!(seen.is_duplicate(0xCAFE_BABE, 160_000, 7));
    }

    /// A different digit at the same instant is a different event.
    ///
    /// The negative case for the event half of the key: two keys pressed in
    /// the same RTP timestamp window are two keypresses, and collapsing them
    /// would lose one.
    #[test]
    fn a_different_event_code_is_a_different_keypress() {
        let mut seen = DtmfDedupe::default();
        assert!(!seen.is_duplicate(0xCAFE_BABE, 160_000, 7));
        assert!(!seen.is_duplicate(0xCAFE_BABE, 160_000, 1));
    }

    /// The same digit later in the call is a new keypress.
    ///
    /// The negative case for the timestamp half. Pressing `7` twice must count
    /// twice; a deduper keyed on the digit alone would report one.
    #[test]
    fn the_same_digit_pressed_again_counts_again() {
        let mut seen = DtmfDedupe::default();
        assert!(!seen.is_duplicate(0xCAFE_BABE, 160_000, 7));
        assert!(!seen.is_duplicate(0xCAFE_BABE, 176_000, 7));
    }

    /// Two streams pressing the same digit at the same offset are distinct.
    ///
    /// The negative case for the SSRC half — both directions of one call, or
    /// two calls in one capture, would otherwise collapse into one.
    #[test]
    fn the_same_digit_on_another_stream_is_a_separate_keypress() {
        let mut seen = DtmfDedupe::default();
        assert!(!seen.is_duplicate(0xCAFE_BABE, 160_000, 7));
        assert!(!seen.is_duplicate(0x0BAD_F00D, 160_000, 7));
    }

    /// The memory is bounded, and forgetting is safe.
    ///
    /// An unbounded set keyed on capture data is a memory-growth path an
    /// attacker controls. Forgetting an old key can only ever re-report a
    /// keypress that is far in the past, which is the harmless direction — so
    /// the bound is deliberately small and this test states the trade.
    #[test]
    fn the_dedupe_memory_is_bounded() {
        let mut seen = DtmfDedupe::default();
        for i in 0..(DtmfDedupe::CAPACITY as u32 * 4) {
            assert!(!seen.is_duplicate(0xCAFE_BABE, i * 1000, 7));
        }
        assert!(
            seen.len() <= DtmfDedupe::CAPACITY,
            "the set must not grow without bound: {}",
            seen.len()
        );
    }

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
        let event = extract_dtmf_with_clock(&payload, 101, 101, 8000, ts());
        let event = event.expect("should extract digit 1");
        assert_eq!(event.digit, '1');
        assert_eq!(event.duration_ms, 200);
    }

    /// Digit 0 is extracted with the correct duration.
    #[test]
    fn extract_digit_0() {
        let payload = build_event(0, true, 10, 800);
        let event = extract_dtmf_with_clock(&payload, 101, 101, 8000, ts())
            .expect("should extract digit 0");
        assert_eq!(event.digit, '0');
        assert_eq!(event.duration_ms, 100);
    }

    /// Event code 10 maps to the `*` digit.
    #[test]
    fn extract_star() {
        let payload = build_event(10, true, 10, 1600);
        let event =
            extract_dtmf_with_clock(&payload, 101, 101, 8000, ts()).expect("should extract *");
        assert_eq!(event.digit, '*');
    }

    /// Event code 11 maps to the `#` digit.
    #[test]
    fn extract_hash() {
        let payload = build_event(11, true, 10, 1600);
        let event =
            extract_dtmf_with_clock(&payload, 101, 101, 8000, ts()).expect("should extract #");
        assert_eq!(event.digit, '#');
    }

    /// Event code 12 maps to the `A` digit.
    #[test]
    fn extract_letter_a() {
        let payload = build_event(12, true, 10, 1600);
        let event =
            extract_dtmf_with_clock(&payload, 101, 101, 8000, ts()).expect("should extract A");
        assert_eq!(event.digit, 'A');
    }

    /// Event code 15 maps to the `D` digit.
    #[test]
    fn extract_letter_d() {
        let payload = build_event(15, true, 10, 1600);
        let event =
            extract_dtmf_with_clock(&payload, 101, 101, 8000, ts()).expect("should extract D");
        assert_eq!(event.digit, 'D');
    }

    /// Intermediate packets (End bit clear) return `None`.
    #[test]
    fn intermediate_packet_not_returned() {
        // E bit = 0 (intermediate)
        let payload = build_event(5, false, 10, 800);
        let event = extract_dtmf_with_clock(&payload, 101, 101, 8000, ts());
        assert!(event.is_none(), "Intermediate packets should return None");
    }

    /// A payload type not matching the negotiated PT returns `None`.
    #[test]
    fn wrong_payload_type_not_returned() {
        let payload = build_event(1, true, 10, 1600);
        // PT 96 doesn't match expected 101
        let event = extract_dtmf_with_clock(&payload, 96, 101, 8000, ts());
        assert!(event.is_none(), "Wrong PT should return None");
    }

    /// A payload under 4 bytes is too short to decode and returns `None`.
    #[test]
    fn payload_too_short() {
        let event = extract_dtmf_with_clock(&[0x01, 0x80], 101, 101, 8000, ts());
        assert!(event.is_none(), "Payload < 4 bytes should return None");
    }

    /// An empty payload returns `None`.
    #[test]
    fn empty_payload() {
        let event = extract_dtmf_with_clock(&[], 101, 101, 8000, ts());
        assert!(event.is_none(), "Empty payload should return None");
    }

    /// An event code outside the DTMF range (16) returns `None`.
    #[test]
    fn invalid_event_code() {
        // Event 16 is outside DTMF range
        let payload = build_event(16, true, 10, 1600);
        let event = extract_dtmf_with_clock(&payload, 101, 101, 8000, ts());
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
            let event = extract_dtmf_with_clock(&payload, 101, 101, 8000, ts())
                .unwrap_or_else(|| panic!("Should extract event code {code}"));
            assert_eq!(
                event.digit, digit,
                "Event code {code} should map to '{digit}'"
            );
        }
    }

    /// Duration in timestamp units is converted to ms against an 8 kHz clock.
    #[test]
    fn duration_calculation() {
        // 3200 timestamp units at 8kHz = 400ms
        let payload = build_event(5, true, 10, 3200);
        let event =
            extract_dtmf_with_clock(&payload, 101, 101, 8000, ts()).expect("should extract");
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

    /// No RFC 4733 event code decodes to the mask character, so a masked log
    /// line can never be misread as a keypress that actually happened.
    ///
    /// This is the property that rules out the obvious mask, `*`: it is event
    /// code 10, so masking with it would make "the caller pressed star" and
    /// "the value is withheld" the same line.
    #[test]
    fn the_mask_character_is_not_a_digit_any_event_code_can_produce() {
        for code in 0u8..=255 {
            assert_ne!(
                event_to_digit(code),
                Some(MASKED_DIGIT),
                "event code {code} decodes to the mask character, so a masked \
                 line is indistinguishable from a real keypress"
            );
        }
    }

    /// A zero clock rate — which no valid `a=rtpmap` carries — returns `None`
    /// rather than dividing by zero.
    #[test]
    fn a_zero_clock_rate_yields_no_event() {
        let payload = build_event(1, true, 10, 1600);
        assert!(extract_dtmf_with_clock(&payload, 101, 101, 0, ts()).is_none());
    }
}
