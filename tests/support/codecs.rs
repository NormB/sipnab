// SPDX-License-Identifier: MIT OR Apache-2.0

//! The audio the synthetic captures carry, and the encoders that put it on
//! the wire.
//!
//! Everything here is integer arithmetic. A tone computed with `f64::sin`
//! rounds through the platform's libm, which is not required to agree to the
//! last bit between Linux, macOS and Windows, and one sample rounded the other
//! way on one host would make a committed capture unreproducible there. So
//! the tones come from one sixteen-entry sine table, and the encoders are the
//! fixed-point algorithms their standards define.
//!
//! * [`g722_encode`] is ITU-T G.722 sub-band ADPCM at 64 kbit/s: the transmit
//!   QMF, a 6-bit lower-band and a 2-bit higher-band ADPCM coder, and the
//!   backward-adaptive predictors both share. sipnab only reads G.722 RTP
//!   headers and never decodes G.722 audio, so there was no encoder to reuse.
//!   `tests/synthetic_captures_test.rs` checks this one byte for byte against
//!   output from two independent implementations, spandsp 0.0.6 and FFmpeg.
//! * [`alaw`] and [`ulaw`] are G.711 as the classic Sun Microsystems
//!   `g711.c` computes it. The suite checks both against sipnab's own G.711
//!   decoder.
#![allow(dead_code)]

/// One period of a sine, sixteen samples long, at full scale:
/// `round(32767 * sin(2 * pi * k / 16))`.
///
/// Sixteen samples is 1 kHz at G.722's 16 kHz input rate and 500 Hz at
/// G.711's 8 kHz. Stepping through the table `m` entries at a time gives `m`
/// times that frequency, still exactly periodic.
pub const SINE16: [i32; 16] = [
    0, 12539, 23170, 30273, 32767, 30273, 23170, 12539, 0, -12539, -23170, -30273, -32767, -30273,
    -23170, -12539,
];

/// Sample `n` of a tone `step` sixteenths of the sample rate, at `amplitude`.
pub fn tone(n: usize, step: usize, amplitude: i32) -> i32 {
    (amplitude * SINE16[(n * step) % 16]) >> 15
}

/// The wideband source signal, sample `n` at 16 kHz: a 1 kHz tone with a
/// quieter 5 kHz tone above it.
///
/// The 5 kHz component sits above the 4 kHz edge of G.722's lower sub-band,
/// so the higher-band coder carries real signal rather than only idle noise.
pub fn wideband_sample(n: usize) -> i16 {
    (tone(n, 1, 12_000) + tone(n, 5, 4_000)) as i16
}

/// The narrowband source signal, sample `n` at 8 kHz: 500 Hz and 1.5 kHz.
pub fn narrowband_sample(n: usize) -> i16 {
    (tone(n, 1, 12_000) + tone(n, 3, 4_000)) as i16
}

// ── G.711 ───────────────────────────────────────────────────────────

/// Segment end points, in the magnitude units each law works in.
const ALAW_SEG_END: [i32; 8] = [0x1F, 0x3F, 0x7F, 0xFF, 0x1FF, 0x3FF, 0x7FF, 0xFFF];
const ULAW_SEG_END: [i32; 8] = [0x3F, 0x7F, 0xFF, 0x1FF, 0x3FF, 0x7FF, 0xFFF, 0x1FFF];

/// The first segment whose end point is at least `value`, or 8 past the end.
fn segment(value: i32, ends: &[i32; 8]) -> i32 {
    ends.iter().position(|end| value <= *end).unwrap_or(8) as i32
}

/// One 16-bit linear sample to G.711 A-law.
pub fn alaw(sample: i16) -> u8 {
    let mut pcm = i32::from(sample) >> 3;
    let mask = if pcm >= 0 {
        0xD5
    } else {
        pcm = -pcm - 1;
        0x55
    };
    let seg = segment(pcm, &ALAW_SEG_END);
    if seg >= 8 {
        return (0x7F ^ mask) as u8;
    }
    let mantissa = if seg < 2 { pcm >> 1 } else { pcm >> seg } & 0x0F;
    (((seg << 4) | mantissa) ^ mask) as u8
}

/// One 16-bit linear sample to G.711 mu-law.
pub fn ulaw(sample: i16) -> u8 {
    const BIAS: i32 = 0x84 >> 2;
    const CLIP: i32 = 8159;
    let mut pcm = i32::from(sample) >> 2;
    let mask = if pcm < 0 {
        pcm = -pcm;
        0x7F
    } else {
        0xFF
    };
    pcm = pcm.min(CLIP) + BIAS;
    let seg = segment(pcm, &ULAW_SEG_END);
    if seg >= 8 {
        return (0x7F ^ mask) as u8;
    }
    (((seg << 4) | ((pcm >> (seg + 1)) & 0x0F)) ^ mask) as u8
}

// ── G.722 ───────────────────────────────────────────────────────────
//
// The tables and blocks below are named as ITU-T G.722 names them: QUANTL,
// INVQAL, LOGSCL and SCALEL for the lower band, their H counterparts for the
// higher band, and block 4 (RECONS, PARREC, UPPOL2, UPPOL1, UPZERO, DELAYA,
// FILTEP, FILTEZ, PREDIC) for the adaptive predictor both bands share.

/// QUANTL decision levels, in units of the scale factor.
const Q6: [i32; 32] = [
    0, 35, 72, 110, 150, 190, 233, 276, 323, 370, 422, 473, 530, 587, 650, 714, 786, 858, 940,
    1023, 1121, 1219, 1339, 1458, 1612, 1765, 1980, 2195, 2557, 2919, 0, 0,
];
/// QUANTL output codes for a negative and a positive difference.
const ILN: [i32; 32] = [
    0, 63, 62, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11,
    10, 9, 8, 7, 6, 5, 4, 0,
];
const ILP: [i32; 32] = [
    0, 61, 60, 59, 58, 57, 56, 55, 54, 53, 52, 51, 50, 49, 48, 47, 46, 45, 44, 43, 42, 41, 40, 39,
    38, 37, 36, 35, 34, 33, 32, 0,
];
/// LOGSCL: log scale factor multipliers, and the 4-bit code to their index.
const WL: [i32; 8] = [-60, -30, 58, 172, 334, 538, 1198, 3042];
const RL42: [usize; 16] = [0, 7, 6, 5, 4, 3, 2, 1, 7, 6, 5, 4, 3, 2, 1, 0];
/// SCALEL/SCALEH: the inverse log table.
const ILB: [i32; 32] = [
    2048, 2093, 2139, 2186, 2233, 2282, 2332, 2383, 2435, 2489, 2543, 2599, 2656, 2714, 2774, 2834,
    2896, 2960, 3025, 3091, 3158, 3228, 3298, 3371, 3444, 3520, 3597, 3676, 3756, 3838, 3922, 4008,
];
/// INVQAL: the 4-bit lower-band inverse quantizer the predictor adapts on.
const QM4: [i32; 16] = [
    0, -20456, -12896, -8968, -6288, -4240, -2584, -1200, 20456, 12896, 8968, 6288, 4240, 2584,
    1200, 0,
];
/// INVQAH, and the higher band's codes, multipliers and index map.
const QM2: [i32; 4] = [-7408, -1616, 7408, 1616];
const IHN: [i32; 3] = [0, 1, 0];
const IHP: [i32; 3] = [0, 3, 2];
const WH: [i32; 3] = [0, -214, 798];
const RH2: [usize; 4] = [2, 1, 2, 1];
/// The 24-tap transmit QMF, as twelve coefficient pairs.
const QMF: [i32; 12] = [3, -11, 12, 32, -210, 951, 3876, -805, 362, -156, 53, -11];

/// Clamp to the 16-bit range, as every ITU fixed-point operation does.
fn sat(x: i32) -> i32 {
    x.clamp(-32768, 32767)
}

/// The adaptive predictor and scale factor state of one sub-band.
#[derive(Clone)]
struct Band {
    s: i32,
    sp: i32,
    sz: i32,
    r: [i32; 3],
    a: [i32; 3],
    ap: [i32; 3],
    p: [i32; 3],
    d: [i32; 7],
    b: [i32; 7],
    bp: [i32; 7],
    sg: [i32; 7],
    nb: i32,
    det: i32,
}

impl Band {
    fn new(det: i32) -> Self {
        Self {
            s: 0,
            sp: 0,
            sz: 0,
            r: [0; 3],
            a: [0; 3],
            ap: [0; 3],
            p: [0; 3],
            d: [0; 7],
            b: [0; 7],
            bp: [0; 7],
            sg: [0; 7],
            nb: 0,
            det,
        }
    }

    /// SCALEL/SCALEH: the scale factor from the log scale factor. `shift` is
    /// 8 for the lower band and 10 for the higher.
    fn rescale(&mut self, shift: i32) {
        let wd1 = ((self.nb >> 6) & 31) as usize;
        let wd2 = shift - (self.nb >> 11);
        let wd3 = if wd2 < 0 {
            ILB[wd1] << -wd2
        } else {
            ILB[wd1] >> wd2
        };
        self.det = wd3 << 2;
    }

    /// Block 4: reconstruct, adapt both predictors, and predict the next
    /// sample, given this sample's quantized difference `d`.
    fn block4(&mut self, d: i32) {
        // RECONS and PARREC
        self.d[0] = d;
        self.r[0] = sat(self.s + d);
        self.p[0] = sat(self.sz + d);

        // UPPOL2
        for i in 0..3 {
            self.sg[i] = self.p[i] >> 15;
        }
        let wd1 = sat(self.a[1] << 2);
        let wd2 = if self.sg[0] == self.sg[1] { -wd1 } else { wd1 }.min(32767);
        let mut wd3 = if self.sg[0] == self.sg[2] { 128 } else { -128 };
        wd3 += wd2 >> 7;
        wd3 += (self.a[2] * 32512) >> 15;
        self.ap[2] = wd3.clamp(-12288, 12288);

        // UPPOL1
        self.sg[0] = self.p[0] >> 15;
        self.sg[1] = self.p[1] >> 15;
        let wd1 = if self.sg[0] == self.sg[1] { 192 } else { -192 };
        let wd2 = (self.a[1] * 32640) >> 15;
        let limit = sat(15360 - self.ap[2]);
        self.ap[1] = sat(wd1 + wd2).clamp(-limit, limit);

        // UPZERO
        let wd1 = if d == 0 { 0 } else { 128 };
        self.sg[0] = d >> 15;
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
}

/// A G.722 encoder at 64 kbit/s, carrying its state across calls so a long
/// signal can be encoded one RTP frame at a time.
pub struct G722Encoder {
    x: [i32; 24],
    low: Band,
    high: Band,
}

impl Default for G722Encoder {
    fn default() -> Self {
        Self::new()
    }
}

impl G722Encoder {
    /// A fresh encoder: silent QMF history, both bands at their reset state.
    pub fn new() -> Self {
        Self {
            x: [0; 24],
            low: Band::new(32),
            high: Band::new(8),
        }
    }

    /// Encode 16 kHz samples, two per output byte. An odd trailing sample is
    /// ignored, as the codec has no half-byte to put it in.
    pub fn encode(&mut self, samples: &[i16]) -> Vec<u8> {
        let mut out = Vec::with_capacity(samples.len() / 2);
        let (pairs, _odd) = samples.as_chunks::<2>();
        for pair in pairs {
            // Transmit QMF: shift two samples in, keep one output per band.
            self.x.copy_within(2.., 0);
            self.x[22] = i32::from(pair[0]);
            self.x[23] = i32::from(pair[1]);
            let (mut sum_odd, mut sum_even) = (0, 0);
            for i in 0..12 {
                sum_odd += self.x[2 * i] * QMF[i];
                sum_even += self.x[2 * i + 1] * QMF[11 - i];
            }
            let xlow = (sum_even + sum_odd) >> 14;
            let xhigh = (sum_even - sum_odd) >> 14;

            // Lower band. SUBTRA, then QUANTL to six bits.
            let el = sat(xlow - self.low.s);
            let wd = if el >= 0 { el } else { -(el + 1) };
            let level = (1..30)
                .find(|&i| wd < (Q6[i] * self.low.det) >> 12)
                .unwrap_or(30);
            let ilow = if el < 0 { ILN[level] } else { ILP[level] };
            // INVQAL on the top four bits, LOGSCL, SCALEL, block 4.
            let ril = (ilow >> 2) as usize;
            let dlow = (self.low.det * QM4[ril]) >> 15;
            self.low.nb = (((self.low.nb * 127) >> 7) + WL[RL42[ril]]).clamp(0, 18432);
            self.low.rescale(8);
            self.low.block4(dlow);

            // Higher band. SUBTRA, then QUANTH to two bits.
            let eh = sat(xhigh - self.high.s);
            let wd = if eh >= 0 { eh } else { -(eh + 1) };
            let mih = if wd >= (564 * self.high.det) >> 12 {
                2
            } else {
                1
            };
            let ihigh = if eh < 0 { IHN[mih] } else { IHP[mih] };
            // INVQAH, LOGSCH, SCALEH, block 4.
            let dhigh = (self.high.det * QM2[ihigh as usize]) >> 15;
            self.high.nb = (((self.high.nb * 127) >> 7) + WH[RH2[ihigh as usize]]).clamp(0, 22528);
            self.high.rescale(10);
            self.high.block4(dhigh);

            out.push(((ihigh << 6) | ilow) as u8);
        }
        out
    }
}

/// Encode a whole 16 kHz signal from a fresh encoder.
pub fn g722_encode(samples: &[i16]) -> Vec<u8> {
    G722Encoder::new().encode(samples)
}
