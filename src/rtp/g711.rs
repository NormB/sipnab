// SPDX-License-Identifier: MIT OR Apache-2.0

//! G.711 mu-law and A-law audio codec decoders (ITU-T G.711).
//!
//! Pure-Rust implementation using hardcoded lookup tables for maximum
//! performance and zero runtime cost. Each encoded byte (0-255) maps
//! directly to a 16-bit signed PCM sample via a single array index.
//!
//! The tables are derived from the ITU-T G.711 specification, scaled to
//! fill the 16-bit linear PCM range:
//!
//! - **mu-law**: Input byte is complemented (XOR 0xFF). Sign bit (bit 7,
//!   1=negative), exponent (bits 4-6), and mantissa (bits 0-3) are extracted.
//!   Magnitude = ((mantissa << 1) | 0x21) << (exponent + 2) - 0x84.
//!   Range: -32124 to +32124.
//!
//! - **A-law**: Input byte is XOR'd with 0x55. Sign bit (bit 7, 1=positive),
//!   exponent (bits 4-6), and mantissa (bits 0-3) are extracted.
//!   For exponent 0: magnitude = ((mantissa << 1) | 1) << 3.
//!   For exponent > 0: magnitude = ((mantissa << 1) | 0x21) << (exponent + 2).
//!   Range: -32256 to +32256.

/// G.711 codec variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum G711Codec {
    /// mu-law (ITU-T G.711 Appendix I, PCMU, RTP payload type 0).
    Ulaw,
    /// A-law (ITU-T G.711 Appendix II, PCMA, RTP payload type 8).
    Alaw,
}

/// Decode a single mu-law sample to 16-bit signed PCM.
#[inline]
pub fn ulaw_to_pcm(sample: u8) -> i16 {
    ULAW_TABLE[sample as usize]
}

/// Decode a single A-law sample to 16-bit signed PCM.
#[inline]
pub fn alaw_to_pcm(sample: u8) -> i16 {
    ALAW_TABLE[sample as usize]
}

/// Decode a frame of G.711 samples to 16-bit signed PCM.
///
/// Each input byte produces one output sample (1:1 mapping, typically 8 kHz).
pub fn decode_frame(codec: G711Codec, input: &[u8]) -> Vec<i16> {
    input
        .iter()
        .map(|&s| match codec {
            G711Codec::Ulaw => ulaw_to_pcm(s),
            G711Codec::Alaw => alaw_to_pcm(s),
        })
        .collect()
}

/// mu-law decode table: 256 entries mapping encoded byte to 16-bit signed PCM.
///
/// Derived from ITU-T G.711 mu-law decoding formula, scaled to 16-bit range.
/// Input is complemented, then decomposed into sign, exponent, and mantissa.
#[rustfmt::skip]
static ULAW_TABLE: [i16; 256] = [
    -32124, -31100, -30076, -29052, -28028, -27004, -25980, -24956, // 0x00..0x07
    -23932, -22908, -21884, -20860, -19836, -18812, -17788, -16764, // 0x08..0x0f
    -15996, -15484, -14972, -14460, -13948, -13436, -12924, -12412, // 0x10..0x17
    -11900, -11388, -10876, -10364,  -9852,  -9340,  -8828,  -8316, // 0x18..0x1f
     -7932,  -7676,  -7420,  -7164,  -6908,  -6652,  -6396,  -6140, // 0x20..0x27
     -5884,  -5628,  -5372,  -5116,  -4860,  -4604,  -4348,  -4092, // 0x28..0x2f
     -3900,  -3772,  -3644,  -3516,  -3388,  -3260,  -3132,  -3004, // 0x30..0x37
     -2876,  -2748,  -2620,  -2492,  -2364,  -2236,  -2108,  -1980, // 0x38..0x3f
     -1884,  -1820,  -1756,  -1692,  -1628,  -1564,  -1500,  -1436, // 0x40..0x47
     -1372,  -1308,  -1244,  -1180,  -1116,  -1052,   -988,   -924, // 0x48..0x4f
      -876,   -844,   -812,   -780,   -748,   -716,   -684,   -652, // 0x50..0x57
      -620,   -588,   -556,   -524,   -492,   -460,   -428,   -396, // 0x58..0x5f
      -372,   -356,   -340,   -324,   -308,   -292,   -276,   -260, // 0x60..0x67
      -244,   -228,   -212,   -196,   -180,   -164,   -148,   -132, // 0x68..0x6f
      -120,   -112,   -104,    -96,    -88,    -80,    -72,    -64, // 0x70..0x77
       -56,    -48,    -40,    -32,    -24,    -16,     -8,      0, // 0x78..0x7f
     32124,  31100,  30076,  29052,  28028,  27004,  25980,  24956, // 0x80..0x87
     23932,  22908,  21884,  20860,  19836,  18812,  17788,  16764, // 0x88..0x8f
     15996,  15484,  14972,  14460,  13948,  13436,  12924,  12412, // 0x90..0x97
     11900,  11388,  10876,  10364,   9852,   9340,   8828,   8316, // 0x98..0x9f
      7932,   7676,   7420,   7164,   6908,   6652,   6396,   6140, // 0xa0..0xa7
      5884,   5628,   5372,   5116,   4860,   4604,   4348,   4092, // 0xa8..0xaf
      3900,   3772,   3644,   3516,   3388,   3260,   3132,   3004, // 0xb0..0xb7
      2876,   2748,   2620,   2492,   2364,   2236,   2108,   1980, // 0xb8..0xbf
      1884,   1820,   1756,   1692,   1628,   1564,   1500,   1436, // 0xc0..0xc7
      1372,   1308,   1244,   1180,   1116,   1052,    988,    924, // 0xc8..0xcf
       876,    844,    812,    780,    748,    716,    684,    652, // 0xd0..0xd7
       620,    588,    556,    524,    492,    460,    428,    396, // 0xd8..0xdf
       372,    356,    340,    324,    308,    292,    276,    260, // 0xe0..0xe7
       244,    228,    212,    196,    180,    164,    148,    132, // 0xe8..0xef
       120,    112,    104,     96,     88,     80,     72,     64, // 0xf0..0xf7
        56,     48,     40,     32,     24,     16,      8,      0, // 0xf8..0xff
];

/// One A-law byte decoded to 16-bit signed PCM, by the ITU-T G.711 rule.
///
/// XOR the byte with 0x55, because A-law transmits every even bit inverted.
/// Bits 4-6 are then the segment and bits 0-3 the mantissa, and bit 7 is the
/// sign: SET is positive. That last rule is the one a hand-typed table got
/// backwards, decoding every A-law call with inverted polarity, so the table
/// is now computed from this function and cannot disagree with it. The Sun
/// `g711.c` that sox and FFmpeg carry decodes the same way.
const fn alaw_decode(byte: u8) -> i16 {
    let a = byte ^ 0x55;
    let segment = (a >> 4) & 0x07;
    let mantissa = (a & 0x0F) as i16;
    let magnitude = if segment == 0 {
        ((mantissa << 1) | 1) << 3
    } else {
        ((mantissa << 1) | 0x21) << (segment + 2)
    };
    if a & 0x80 != 0 { magnitude } else { -magnitude }
}

/// A-law decode table: 256 entries mapping encoded byte to 16-bit signed PCM,
/// each computed by [`alaw_decode`] at compile time.
static ALAW_TABLE: [i16; 256] = {
    let mut table = [0i16; 256];
    let mut byte = 0usize;
    while byte < 256 {
        table[byte] = alaw_decode(byte as u8);
        byte += 1;
    }
    table
};

/// Unit tests for the G.711 mu-law and A-law decode tables.
#[cfg(test)]
mod tests {
    use super::*;

    /// mu-law byte 0xFF decodes to exactly zero (digital silence).
    #[test]
    fn ulaw_silence() {
        // mu-law 0xFF is digital silence (decodes to exactly 0)
        assert_eq!(ulaw_to_pcm(0xFF), 0);
    }

    /// mu-law byte 0x80 decodes to the maximum positive PCM value.
    #[test]
    fn ulaw_max_positive() {
        // mu-law 0x80 decodes to the largest positive value
        assert_eq!(ulaw_to_pcm(0x80), 32124);
    }

    /// A-law byte 0xD5 decodes near zero (digital silence).
    #[test]
    fn alaw_silence() {
        // A-law 0xD5 is digital silence (decodes near zero)
        let sample = alaw_to_pcm(0xD5);
        assert!(
            sample.unsigned_abs() <= 8,
            "A-law silence 0xD5 should decode near zero, got {sample}"
        );
    }

    /// Decoding a mu-law frame yields the expected per-byte PCM samples.
    #[test]
    fn decode_frame_ulaw() {
        let input = [0xFF, 0x80, 0x00, 0x7F];
        let pcm = decode_frame(G711Codec::Ulaw, &input);
        assert_eq!(pcm.len(), 4);
        assert_eq!(pcm[0], 0); // silence
        assert_eq!(pcm[1], 32124); // max positive
        assert_eq!(pcm[2], -32124); // max negative
        assert_eq!(pcm[3], 0); // near-silence
    }

    /// Decoding an A-law frame yields the expected per-byte PCM samples.
    #[test]
    fn decode_frame_alaw() {
        let input = [0xD5, 0x55, 0x80, 0x00];
        let pcm = decode_frame(G711Codec::Alaw, &input);
        assert_eq!(pcm.len(), 4);
        assert_eq!(pcm[0], 8); // near-silence, positive
        assert_eq!(pcm[1], -8); // near-silence, negative
        assert_eq!(pcm[2], 5504); // positive value
        assert_eq!(pcm[3], -5504); // negative value
    }

    /// A-law's sign is the one ITU-T G.711 defines, not its inverse.
    ///
    /// G.711 A-law transmits every even bit inverted, so a decoder XORs the
    /// byte with 0x55 and then reads bit 7 as the sign: SET means positive.
    /// The table had it the other way round, so every A-law call decoded with
    /// inverted polarity. The magnitudes were right, which is why no level,
    /// clip or MOS figure noticed. The reference decoders agree with the
    /// standard: the Sun `g711.c` that sox and FFmpeg carry decode 0xD5 to +8
    /// and 0x55 to -8.
    #[test]
    fn alaw_decode_sign_matches_itu_g711() {
        assert_eq!(alaw_to_pcm(0x00), -5504);
        assert_eq!(alaw_to_pcm(0x55), -8);
        assert_eq!(alaw_to_pcm(0xD5), 8);
        assert_eq!(alaw_to_pcm(0x80), 5504);
        for b in 0u8..=255 {
            assert_eq!(
                alaw_to_pcm(b),
                -alaw_to_pcm(b ^ 0x80),
                "A-law 0x{b:02x} and 0x{:02x} differ only in sign",
                b ^ 0x80
            );
            let negative = (b ^ 0x55) & 0x80 == 0;
            assert_eq!(
                alaw_to_pcm(b) < 0,
                negative,
                "A-law 0x{b:02x} decoded to {}: after XOR 0x55, bit 7 clear is negative",
                alaw_to_pcm(b)
            );
        }
    }

    /// The mu-law positive and negative halves are exact mirror images.
    #[test]
    fn ulaw_positive_negative_symmetry() {
        // The positive half (0x80..0xFF) and negative half (0x00..0x7F)
        // are mirror images of each other.
        for i in 0u8..128 {
            let neg = ulaw_to_pcm(i);
            let pos = ulaw_to_pcm(i + 128);
            assert_eq!(
                neg, -pos,
                "mu-law symmetry broken at index {i}: {neg} != -{pos}"
            );
        }
    }

    /// Decoding an empty input frame yields an empty PCM vector.
    #[test]
    fn decode_frame_empty() {
        let pcm = decode_frame(G711Codec::Ulaw, &[]);
        assert!(pcm.is_empty());
    }

    /// The mu-law positive half decreases monotonically toward silence.
    #[test]
    fn ulaw_monotonic_positive() {
        // Within the positive half, values should decrease monotonically
        // from 0x80 (max) toward 0xFF (silence/zero).
        for i in 0x80u8..0xFE {
            assert!(
                ulaw_to_pcm(i) >= ulaw_to_pcm(i + 1),
                "mu-law not monotonic at 0x{i:02x}: {} < {}",
                ulaw_to_pcm(i),
                ulaw_to_pcm(i + 1)
            );
        }
    }
}
