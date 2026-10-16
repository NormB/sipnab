// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bit-stream layer: RFC 3551 section 4.5.6 (Figure 4) packing of G.729
//! Table 8 and Annex B Table B.2, the 10n / 10n+2 payload rule, and the
//! ITU-T G.192 serial format of the test vectors.

pub mod common;

use g729::bitstream::{self, G192Error, SerialFrame, SidParams, SpeechParams};

#[test]
fn speech_fields_follow_table_8_msb_first() -> common::TestResult {
    // L0 is the first bit of the frame.
    let mut b = [0u8; 10];
    b[0] = 0x80;
    assert_eq!(SpeechParams::unpack(&b).l, [1, 0, 0, 0]);
    // L1 is the next 7 bits.
    b[0] = 0x7f;
    assert_eq!(SpeechParams::unpack(&b).l, [0, 127, 0, 0]);
    // GB2 is the last 4 bits.
    let mut b = [0u8; 10];
    b[9] = 0x0f;
    let p = SpeechParams::unpack(&b);
    assert_eq!(p.gb[1], 15);
    assert_eq!(p.ga[1], 0);
    // All ones: every field at its maximum.
    let p = SpeechParams::unpack(&[0xff; 10]);
    assert_eq!(p.l, [1, 127, 31, 31]);
    assert_eq!((p.p1, p.p0, p.p2), (255, 1, 31));
    assert_eq!((p.c, p.s), ([8191, 8191], [15, 15]));
    assert_eq!((p.ga, p.gb), ([7, 7], [15, 15]));
    Ok(())
}

#[test]
fn speech_fields_split_at_the_table_8_widths() -> common::TestResult {
    // A walking pattern: bit k of the frame set, for each field boundary.
    // Widths in transmission order: L0 1, L1 7, L2 5, L3 5, P1 8, P0 1,
    // C1 13, S1 4, GA1 3, GB1 4, P2 5, C2 13, S2 4, GA2 3, GB2 4.
    let widths = [1usize, 7, 5, 5, 8, 1, 13, 4, 3, 4, 5, 13, 4, 3, 4];
    assert_eq!(widths.iter().sum::<usize>(), 80);
    let mut start = 0;
    for (field, &w) in widths.iter().enumerate() {
        // Set the LSB of this field only.
        let bit = start + w - 1;
        let mut b = [0u8; 10];
        b[bit / 8] = 0x80 >> (bit % 8);
        let p = SpeechParams::unpack(&b);
        let values = [
            p.l[0], p.l[1], p.l[2], p.l[3], p.p1, p.p0, p.c[0], p.s[0], p.ga[0], p.gb[0], p.p2,
            p.c[1], p.s[1], p.ga[1], p.gb[1],
        ];
        for (k, v) in values.iter().enumerate() {
            assert_eq!(*v, u16::from(k == field), "field {k} with bit {bit} set");
        }
        start += w;
    }
    Ok(())
}

#[test]
fn sid_fields_follow_table_b2_in_the_first_15_bits() -> common::TestResult {
    // Switched predictor (1), stage 1 (5), stage 2 (4), energy (5); the 16th
    // bit of the two octets is padding.
    // Bits: 1 | 00001 | 0001 | 00001 | pad 1 = 1000_0100 0100_0011.
    let p = SidParams::unpack(&[0x84, 0x43]);
    assert_eq!(
        p,
        SidParams {
            switch: 1,
            stage1: 1,
            stage2: 1,
            energy: 1
        }
    );
    let p = SidParams::unpack(&[0xff, 0xfe]);
    assert_eq!(
        p,
        SidParams {
            switch: 1,
            stage1: 31,
            stage2: 15,
            energy: 31
        }
    );
    // The padding bit is ignored.
    assert_eq!(SidParams::unpack(&[0, 1]), SidParams::unpack(&[0, 0]));
    Ok(())
}

#[test]
fn rtp_payloads_are_10n_or_10n_plus_2_octets() -> common::TestResult {
    for len in 0..64usize {
        let ok = len % 10 == 0 || len % 10 == 2;
        assert_eq!(
            bitstream::split_rtp(&vec![0u8; len]).is_ok(),
            ok,
            "length {len}"
        );
    }
    let payload = vec![0u8; 22];
    let (frames, sid) = bitstream::split_rtp(&payload).map_err(|e| format!("{e:?}"))?;
    assert_eq!(frames.len(), 2);
    assert!(sid.is_some());
    let (frames, sid) = bitstream::split_rtp(&[0u8; 2]).map_err(|e| format!("{e:?}"))?;
    assert!(frames.is_empty() && sid.is_some());
    let (frames, sid) = bitstream::split_rtp(&[0u8; 30]).map_err(|e| format!("{e:?}"))?;
    assert!(frames.len() == 3 && sid.is_none());
    Ok(())
}

fn g192(words: &[u16]) -> Vec<u8> {
    words.iter().flat_map(|w| w.to_le_bytes()).collect()
}

fn bits(n: usize, pattern: impl Fn(usize) -> bool) -> Vec<u16> {
    (0..n)
        .map(|k| if pattern(k) { 0x0081 } else { 0x007f })
        .collect()
}

#[test]
fn g192_frames_of_each_kind() -> common::TestResult {
    let mut words = vec![0x6b21, 80];
    words.extend(bits(80, |k| k == 0 || k == 79));
    words.extend([0x6b21, 16]);
    words.extend(bits(16, |k| k == 0));
    words.extend([0x6b21, 0]);
    // An erased speech frame: all-zero bit words (clause C2 of the spec).
    words.extend([0x6b21, 80]);
    words.extend(vec![0u16; 80]);
    // An erased SID frame.
    words.extend([0x6b21, 16]);
    words.extend(vec![0u16; 16]);
    // Sync 0x6B20 is erased whatever follows.
    words.extend([0x6b20, 0]);
    let parsed: Vec<SerialFrame> = bitstream::g192_frames(&g192(&words))
        .collect::<Result<_, _>>()
        .map_err(|e| e.to_string())?;
    let mut first = [0u8; 10];
    first[0] = 0x80;
    first[9] = 0x01;
    assert_eq!(
        parsed,
        vec![
            SerialFrame::Speech(first),
            SerialFrame::Sid([0x80, 0x00]),
            SerialFrame::NoTx,
            SerialFrame::Erased,
            SerialFrame::Erased,
            SerialFrame::Erased,
        ]
    );
    Ok(())
}

#[test]
fn g192_refuses_malformed_input() -> common::TestResult {
    // Any first word other than 0x6B21 marks an erased frame (the oracle's
    // note on the reference's serial reader); its size word still counts
    // the words that follow.
    let other_sync = g192(&[0x1234, 0, 0x6b21, 0, 0x0000, 2, 0x81, 0x7f]);
    let parsed: Vec<SerialFrame> = bitstream::g192_frames(&other_sync)
        .collect::<Result<_, _>>()
        .map_err(|e| e.to_string())?;
    assert_eq!(
        parsed,
        vec![SerialFrame::Erased, SerialFrame::NoTx, SerialFrame::Erased]
    );
    let mut short = g192(&[0x6b21, 80]);
    short.extend(g192(&bits(10, |_| true)));
    assert!(matches!(
        bitstream::g192_frames(&short).next(),
        Some(Err(G192Error::Truncated { .. }))
    ));
    let bad_len = g192(&[0x6b21, 7, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81]);
    assert!(matches!(
        bitstream::g192_frames(&bad_len).next(),
        Some(Err(G192Error::Length { .. }))
    ));
    let bad_word = g192(&[
        0x6b21, 16, 0x1234, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ]);
    assert!(matches!(
        bitstream::g192_frames(&bad_word).next(),
        Some(Err(G192Error::BitWord { .. }))
    ));
    let odd = [0x21u8];
    assert!(matches!(
        bitstream::g192_frames(&odd).next(),
        Some(Err(G192Error::Truncated { .. }))
    ));
    Ok(())
}

#[test]
fn the_vector_files_parse_completely() -> common::TestResult {
    // Every frame of all 16 decoder inputs parses; frame counts match the
    // expected outputs (80 samples each).
    for (bit, out) in common::PAIRS {
        let input = common::read_vector(bit)?;
        let frames: Vec<SerialFrame> = bitstream::g192_frames(&input)
            .collect::<Result<_, _>>()
            .map_err(|e| format!("{bit}: {e}"))?;
        let samples = common::read_vector(out)?.len() / 2;
        assert_eq!(frames.len() * 80, samples, "{bit}");
    }
    Ok(())
}

#[test]
fn each_serial_frame_becomes_the_decoder_frame_of_its_kind() -> common::TestResult {
    use g729::Frame;
    let speech = [0x5au8; 10];
    let sid = [0xa4u8, 0x02];
    assert_eq!(SerialFrame::Speech(speech).frame(), Frame::Voice(&speech));
    assert_eq!(SerialFrame::Sid(sid).frame(), Frame::Sid(&sid));
    assert_eq!(SerialFrame::NoTx.frame(), Frame::NoTx);
    assert_eq!(SerialFrame::Erased.frame(), Frame::Erased);
    Ok(())
}
