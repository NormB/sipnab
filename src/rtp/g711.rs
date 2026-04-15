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
//! - **A-law**: Input byte is XOR'd with 0x55. Sign bit (bit 7, 1=negative),
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

/// A-law decode table: 256 entries mapping encoded byte to 16-bit signed PCM.
///
/// Derived from ITU-T G.711 A-law decoding formula, scaled to 16-bit range.
/// Input is XOR'd with 0x55, then decomposed into sign, exponent, and mantissa.
#[rustfmt::skip]
static ALAW_TABLE: [i16; 256] = [
      5504,   5248,   6016,   5760,   4480,   4224,   4992,   4736, // 0x00..0x07
      7552,   7296,   8064,   7808,   6528,   6272,   7040,   6784, // 0x08..0x0f
      2752,   2624,   3008,   2880,   2240,   2112,   2496,   2368, // 0x10..0x17
      3776,   3648,   4032,   3904,   3264,   3136,   3520,   3392, // 0x18..0x1f
     22016,  20992,  24064,  23040,  17920,  16896,  19968,  18944, // 0x20..0x27
     30208,  29184,  32256,  31232,  26112,  25088,  28160,  27136, // 0x28..0x2f
     11008,  10496,  12032,  11520,   8960,   8448,   9984,   9472, // 0x30..0x37
     15104,  14592,  16128,  15616,  13056,  12544,  14080,  13568, // 0x38..0x3f
       344,    328,    376,    360,    280,    264,    312,    296, // 0x40..0x47
       472,    456,    504,    488,    408,    392,    440,    424, // 0x48..0x4f
        88,     72,    120,    104,     24,      8,     56,     40, // 0x50..0x57
       216,    200,    248,    232,    152,    136,    184,    168, // 0x58..0x5f
      1376,   1312,   1504,   1440,   1120,   1056,   1248,   1184, // 0x60..0x67
      1888,   1824,   2016,   1952,   1632,   1568,   1760,   1696, // 0x68..0x6f
       688,    656,    752,    720,    560,    528,    624,    592, // 0x70..0x77
       944,    912,   1008,    976,    816,    784,    880,    848, // 0x78..0x7f
     -5504,  -5248,  -6016,  -5760,  -4480,  -4224,  -4992,  -4736, // 0x80..0x87
     -7552,  -7296,  -8064,  -7808,  -6528,  -6272,  -7040,  -6784, // 0x88..0x8f
     -2752,  -2624,  -3008,  -2880,  -2240,  -2112,  -2496,  -2368, // 0x90..0x97
     -3776,  -3648,  -4032,  -3904,  -3264,  -3136,  -3520,  -3392, // 0x98..0x9f
    -22016, -20992, -24064, -23040, -17920, -16896, -19968, -18944, // 0xa0..0xa7
    -30208, -29184, -32256, -31232, -26112, -25088, -28160, -27136, // 0xa8..0xaf
    -11008, -10496, -12032, -11520,  -8960,  -8448,  -9984,  -9472, // 0xb0..0xb7
    -15104, -14592, -16128, -15616, -13056, -12544, -14080, -13568, // 0xb8..0xbf
      -344,   -328,   -376,   -360,   -280,   -264,   -312,   -296, // 0xc0..0xc7
      -472,   -456,   -504,   -488,   -408,   -392,   -440,   -424, // 0xc8..0xcf
       -88,    -72,   -120,   -104,    -24,     -8,    -56,    -40, // 0xd0..0xd7
      -216,   -200,   -248,   -232,   -152,   -136,   -184,   -168, // 0xd8..0xdf
     -1376,  -1312,  -1504,  -1440,  -1120,  -1056,  -1248,  -1184, // 0xe0..0xe7
     -1888,  -1824,  -2016,  -1952,  -1632,  -1568,  -1760,  -1696, // 0xe8..0xef
      -688,   -656,   -752,   -720,   -560,   -528,   -624,   -592, // 0xf0..0xf7
      -944,   -912,  -1008,   -976,   -816,   -784,   -880,   -848, // 0xf8..0xff
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ulaw_silence() {
        // mu-law 0xFF is digital silence (decodes to exactly 0)
        assert_eq!(ulaw_to_pcm(0xFF), 0);
    }

    #[test]
    fn ulaw_max_positive() {
        // mu-law 0x80 decodes to the largest positive value
        assert_eq!(ulaw_to_pcm(0x80), 32124);
    }

    #[test]
    fn alaw_silence() {
        // A-law 0xD5 is digital silence (decodes near zero)
        let sample = alaw_to_pcm(0xD5);
        assert!(
            sample.unsigned_abs() <= 8,
            "A-law silence 0xD5 should decode near zero, got {sample}"
        );
    }

    #[test]
    fn decode_frame_ulaw() {
        let input = [0xFF, 0x80, 0x00, 0x7F];
        let pcm = decode_frame(G711Codec::Ulaw, &input);
        assert_eq!(pcm.len(), 4);
        assert_eq!(pcm[0], 0);       // silence
        assert_eq!(pcm[1], 32124);   // max positive
        assert_eq!(pcm[2], -32124);  // max negative
        assert_eq!(pcm[3], 0);       // near-silence
    }

    #[test]
    fn decode_frame_alaw() {
        let input = [0xD5, 0x55, 0x80, 0x00];
        let pcm = decode_frame(G711Codec::Alaw, &input);
        assert_eq!(pcm.len(), 4);
        assert_eq!(pcm[0], -8);     // near-silence
        assert_eq!(pcm[1], 8);      // near-silence (opposite polarity)
        assert_eq!(pcm[2], -5504);  // negative value
        assert_eq!(pcm[3], 5504);   // positive value
    }

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

    #[test]
    fn decode_frame_empty() {
        let pcm = decode_frame(G711Codec::Ulaw, &[]);
        assert!(pcm.is_empty());
    }

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
