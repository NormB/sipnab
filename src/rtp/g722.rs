// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! ITU-T G.722 decoding: 64 kbit/s sub-band ADPCM to 16 kHz 16-bit PCM.
//!
//! Each input byte carries one 6-bit low-band code and one 2-bit high-band
//! code and decodes to two 16 kHz samples. The block names in the comments
//! (INVQBL, LOGSCL, ...) are those of ITU-T Recommendation G.722 (09/2012),
//! section 6; the arithmetic is the Recommendation's 16-bit fixed point,
//! saturation included, because a decoder that rounds differently drifts from
//! every other implementation within a few samples.
//!
//! Only the 64 kbit/s mode is decoded: it is the mode SIP endpoints use
//! ([RFC 3551 section 4.5.2](https://www.rfc-editor.org/rfc/rfc3551.html#section-4.5.2) assigns static payload type 9 to it).

/// Low-band log-scale factor increments (WL), by 3-bit magnitude.
const WL: [i32; 8] = [-60, -30, 58, 172, 334, 538, 1198, 3042];
/// 4-bit low-band code to its 3-bit magnitude for the log scale (RIL4/RL42).
const RL42: [usize; 16] = [0, 7, 6, 5, 4, 3, 2, 1, 7, 6, 5, 4, 3, 2, 1, 0];
/// Inverse log base-2 table (ILB) for the scale factors.
const ILB: [i32; 32] = [
    2048, 2093, 2139, 2186, 2233, 2282, 2332, 2383, 2435, 2489, 2543, 2599, 2656, 2714, 2774, 2834,
    2896, 2960, 3025, 3091, 3158, 3228, 3298, 3371, 3444, 3520, 3597, 3676, 3756, 3838, 3922, 4008,
];
/// High-band log-scale factor increments (WH).
const WH: [i32; 3] = [0, -214, 798];
/// 2-bit high-band code to its magnitude for the log scale (RH2).
const RH2: [usize; 4] = [2, 1, 2, 1];
/// High-band inverse quantizer outputs (QM2).
const QM2: [i32; 4] = [-7408, -1616, 7408, 1616];
/// Low-band inverse quantizer outputs, 4-bit (QM4), for the predictor.
const QM4: [i32; 16] = [
    0, -20456, -12896, -8968, -6288, -4240, -2584, -1200, 20456, 12896, 8968, 6288, 4240, 2584,
    1200, 0,
];
/// Low-band inverse quantizer outputs, 6-bit (QM6), for the reconstruction.
const QM6: [i32; 64] = [
    -136, -136, -136, -136, -24808, -21904, -19008, -16704, -14984, -13512, -12280, -11192, -10232,
    -9360, -8576, -7856, -7192, -6576, -6000, -5456, -4944, -4464, -4008, -3576, -3168, -2776,
    -2400, -2032, -1688, -1360, -1040, -728, 24808, 21904, 19008, 16704, 14984, 13512, 12280,
    11192, 10232, 9360, 8576, 7856, 7192, 6576, 6000, 5456, 4944, 4464, 4008, 3576, 3168, 2776,
    2400, 2032, 1688, 1360, 1040, 728, 432, 136, -432, -136,
];
/// Receive QMF coefficients.
const QMF: [i32; 12] = [3, -11, 12, 32, -210, 951, 3876, -805, 362, -156, 53, -11];

/// `v` clamped to the 16-bit range, as the Recommendation's arithmetic does.
fn sat(v: i32) -> i32 {
    v.clamp(i32::from(i16::MIN), i32::from(i16::MAX))
}

/// One sub-band's adaptive predictor and scale factor.
#[derive(Debug, Clone, Default)]
struct Band {
    /// Signal estimate (PREDIC).
    s: i32,
    /// Pole section's part of the estimate (FILTEP).
    sp: i32,
    /// Zero section's part of the estimate (FILTEZ).
    sz: i32,
    /// Reconstructed signal, current and two past (RECONS).
    r: [i32; 3],
    /// Pole predictor coefficients; index 0 unused.
    a: [i32; 3],
    /// Pole predictor coefficients being updated (UPPOL1, UPPOL2).
    ap: [i32; 3],
    /// Partially reconstructed signal, current and two past (PARREC).
    p: [i32; 3],
    /// Quantized difference signal, current and six past.
    d: [i32; 7],
    /// Zero predictor coefficients; index 0 unused.
    b: [i32; 7],
    /// Zero predictor coefficients being updated (UPZERO).
    bp: [i32; 7],
    /// Signs of the values the updates compare.
    sg: [i32; 7],
    /// Log scale factor (LOGSCL, LOGSCH).
    nb: i32,
    /// Scale factor (SCALEL, SCALEH).
    det: i32,
}

impl Band {
    /// Blocks 4L/4H: update the pole and zero predictors with the quantized
    /// difference `dx` and compute the next signal estimate.
    fn adapt(&mut self, dx: i32) {
        // RECONS and PARREC. The clamp on `s + dx` is the Recommendation's;
        // neither test stream reaches it, full-scale noise included, and it is
        // kept so the arithmetic stays the Recommendation's everywhere.
        self.d[0] = dx;
        self.r[0] = sat(self.s + dx);
        self.p[0] = sat(self.sz + dx);

        // UPPOL2
        for i in 0..3 {
            self.sg[i] = self.p[i] >> 15;
        }
        let wd1 = sat(self.a[1] << 2);
        let wd2 = if self.sg[0] == self.sg[1] { -wd1 } else { wd1 }.min(32767);
        let mut wd3 = (wd2 >> 7) + if self.sg[0] == self.sg[2] { 128 } else { -128 };
        wd3 += (self.a[2] * 32512) >> 15;
        self.ap[2] = wd3.clamp(-12288, 12288);

        // UPPOL1
        self.sg[0] = self.p[0] >> 15;
        self.sg[1] = self.p[1] >> 15;
        let wd1 = if self.sg[0] == self.sg[1] { 192 } else { -192 };
        let wd2 = (self.a[1] * 32640) >> 15;
        self.ap[1] = sat(wd1 + wd2);
        let wd3 = sat(15360 - self.ap[2]);
        self.ap[1] = self.ap[1].clamp(-wd3, wd3);

        // UPZERO
        let wd1 = if dx == 0 { 0 } else { 128 };
        self.sg[0] = dx >> 15;
        for i in 1..7 {
            self.sg[i] = self.d[i] >> 15;
            let wd2 = if self.sg[i] == self.sg[0] { wd1 } else { -wd1 };
            let wd3 = (self.b[i] * 32640) >> 15;
            self.bp[i] = sat(wd2 + wd3);
        }

        // DELAYA
        for i in (1..7).rev() {
            self.d[i] = self.d[i - 1];
            self.b[i] = self.bp[i];
        }
        for i in (1..3).rev() {
            self.r[i] = self.r[i - 1];
            self.p[i] = self.p[i - 1];
            self.a[i] = self.ap[i];
        }

        // FILTEP
        let wd1 = (self.a[1] * sat(self.r[1] + self.r[1])) >> 15;
        let wd2 = (self.a[2] * sat(self.r[2] + self.r[2])) >> 15;
        self.sp = sat(wd1 + wd2);

        // FILTEZ
        let mut sz = 0;
        for i in (1..7).rev() {
            sz += (self.b[i] * sat(self.d[i] + self.d[i])) >> 15;
        }
        self.sz = sat(sz);

        // PREDIC
        self.s = sat(self.sp + self.sz);
    }

    /// Blocks 3L/3H, SCALEL/SCALEH: the scale factor from the log scale.
    fn scale(&mut self, shift_base: i32) {
        let wd1 = ((self.nb >> 6) & 31) as usize;
        let wd2 = shift_base - (self.nb >> 11);
        let wd3 = if wd2 < 0 {
            ILB[wd1] << -wd2
        } else {
            ILB[wd1] >> wd2
        };
        self.det = wd3 << 2;
    }
}

/// A G.722 decoder. It carries the sub-band predictors and the receive QMF's
/// history from one call to the next, so one decoder decodes one stream.
#[derive(Debug, Clone)]
pub struct Decoder {
    /// The lower sub-band, 0 to 4 kHz.
    low: Band,
    /// The higher sub-band, 4 to 8 kHz.
    high: Band,
    /// The receive QMF's last 24 inputs.
    x: [i32; 24],
}

impl Default for Decoder {
    fn default() -> Self {
        Self {
            low: Band {
                det: 32,
                ..Band::default()
            },
            high: Band {
                det: 8,
                ..Band::default()
            },
            x: [0; 24],
        }
    }
}

impl Decoder {
    /// Decode `bytes` of 64 kbit/s G.722 into 16 kHz samples, two per byte.
    pub fn decode(&mut self, bytes: &[u8]) -> Vec<i16> {
        let mut out = Vec::with_capacity(bytes.len() * 2);
        for &code in bytes {
            let code = i32::from(code);
            let ilow = (code & 0x3F) as usize;
            let ihigh = ((code >> 6) & 0x03) as usize;

            // INVQBL and RECONS, low band
            let wd2 = (self.low.det * QM6[ilow]) >> 15;
            let rlow = (self.low.s + wd2).clamp(-16384, 16383);

            // INVQAL
            let ilow4 = ilow >> 2;
            let dlowt = (self.low.det * QM4[ilow4]) >> 15;

            // LOGSCL
            let wd1 = ((self.low.nb * 127) >> 7) + WL[RL42[ilow4]];
            self.low.nb = wd1.clamp(0, 18432);
            self.low.scale(8);
            self.low.adapt(dlowt);

            // INVQAH and RECONS, high band
            let dhigh = (self.high.det * QM2[ihigh]) >> 15;
            let rhigh = (dhigh + self.high.s).clamp(-16384, 16383);

            // LOGSCH
            let wd1 = ((self.high.nb * 127) >> 7) + WH[RH2[ihigh]];
            self.high.nb = wd1.clamp(0, 22528);
            self.high.scale(10);
            self.high.adapt(dhigh);

            // Receive QMF
            self.x.copy_within(2..24, 0);
            self.x[22] = rlow + rhigh;
            self.x[23] = rlow - rhigh;
            let mut xout1 = 0i32;
            let mut xout2 = 0i32;
            for i in 0..12 {
                xout2 += self.x[2 * i] * QMF[i];
                xout1 += self.x[2 * i + 1] * QMF[11 - i];
            }
            out.push(sat(xout1 >> 11) as i16);
            out.push(sat(xout2 >> 11) as i16);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestError = Box<dyn std::error::Error>;

    /// The decoder reproduces an independent G.722 implementation's output
    /// sample for sample: FFmpeg's decode of the same bitstream (see
    /// `tests/fixtures/g722/README.md`).
    #[test]
    fn the_decoder_matches_an_independent_implementation() -> Result<(), TestError> {
        let encoded = std::fs::read("tests/fixtures/g722/tone440.g722")?;
        let expected: Vec<i16> = std::fs::read("tests/fixtures/g722/tone440.s16le")?
            .as_chunks::<2>()
            .0
            .iter()
            .map(|b| i16::from_le_bytes(*b))
            .collect();
        let mut decoder = Decoder::default();
        let decoded = decoder.decode(&encoded);
        assert_eq!(decoded.len(), encoded.len() * 2, "two samples per byte");
        assert_eq!(decoded.len(), expected.len());
        let first_difference = decoded.iter().zip(&expected).position(|(a, b)| a != b);
        assert_eq!(first_difference, None, "every sample matches");
        Ok(())
    }

    /// Full-scale noise drives the predictors and the output to their limits,
    /// where a decoder that saturates differently from the Recommendation
    /// parts company with every other implementation. FFmpeg's decode of it
    /// reaches both 16-bit limits 134 times.
    #[test]
    fn the_decoder_matches_at_full_scale() -> Result<(), TestError> {
        let encoded = std::fs::read("tests/fixtures/g722/noise-fullscale.g722")?;
        let expected: Vec<i16> = std::fs::read("tests/fixtures/g722/noise-fullscale.s16le")?
            .as_chunks::<2>()
            .0
            .iter()
            .map(|b| i16::from_le_bytes(*b))
            .collect();
        let decoded = Decoder::default().decode(&encoded);
        assert_eq!(decoded.len(), expected.len());
        let first_difference = decoded.iter().zip(&expected).position(|(a, b)| a != b);
        assert_eq!(first_difference, None, "every sample matches");
        Ok(())
    }

    /// The decoder carries its state across calls, so a stream decoded in
    /// RTP-sized pieces equals the stream decoded at once.
    #[test]
    fn decoding_in_pieces_equals_decoding_at_once() -> Result<(), TestError> {
        let encoded = std::fs::read("tests/fixtures/g722/tone440.g722")?;
        let whole = Decoder::default().decode(&encoded);
        let mut decoder = Decoder::default();
        let pieces: Vec<i16> = encoded
            .chunks(160)
            .flat_map(|chunk| decoder.decode(chunk))
            .collect();
        assert_eq!(pieces, whole);
        Ok(())
    }
}
