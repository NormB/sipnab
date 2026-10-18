// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! Annex B comfort-noise generation: decoding of the SID LSF parameters
//! (G.729 clause B.4.2.2, the MA predictor of equation (B.18)) and SID gain
//! (clause B.4.2.1), the target-gain smoothing of equation (B.19), the
//! comfort-noise excitation of clause B.4.4 (a random adaptive and ACELP
//! excitation plus a Gaussian excitation, equations (B.20) to (B.23)), and
//! the recovery of a lost first SID frame of clause B.4.5.
//!
//! Established from the oracle's traces: the order and bit layout of the
//! random draws, the composition of the excitation, the gain smoothing, the
//! saved excitation energy, and that the comfort-noise LSP vector is the last
//! decoded SID vector (also when the first SID frame is lost). The Gaussian
//! scaling, the fixed gain of equations (B.20) to (B.23) and the recovery of a
//! lost first SID gain follow, step by step, the oracle's round-2 traces.
//!
//! Where the reference differs from the text: E_x and I of equation (B.21) are
//! computed on the mixed excitation Ga ea(n) + ex2(n), not on ea(n) alone;
//! when (B.21) has no real root, Ga is set to 0 and Gf solves for ex2(n) alone
//! with the energy (1 - alpha^2) K; and the comfort-noise LSP vector after a
//! lost first SID frame is the last SID vector, not the last active frame's
//! (clause B.4.5).

use crate::basic_op::{Ctx, abs_s, extract_h, extract_l, norm_l};
use crate::bitstream::SidParams;
use crate::tables::{Scalar, Tables, formula, text};
use crate::{Decoder, FRAME_SAMPLES, adaptive, fixed, lpc, lsp};

/// Draws of the generator per subframe: delay and pulses (2), adaptive gain
/// (1), Gaussian excitation (40 samples of 12 draws).
pub const DRAWS_PER_SUBFRAME: usize = 3 + 40 * GAUSS_DRAWS;
const GAUSS_DRAWS: usize = 12;

/// The comfort-noise generator's state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CngState {
    /// Generator seed, reset at every active frame.
    pub(crate) noise_seed: i16,
    /// The comfort-noise LSP vector in force (the last SID vector).
    pub(crate) q_sid: [i16; 10],
    /// Decoded SID gain G~sid, Q3.
    pub(crate) g_sid: i16,
    /// Smoothed target gain G~t, Q3 (equation (B.19)).
    pub(crate) g_target: i16,
    /// Energy of the excitation of the last good frame: (mantissa, exponent).
    pub(crate) saved_excitation_energy: (i16, i16),
}

impl CngState {
    /// Initial state.
    ///
    /// # Panics
    ///
    /// Does not panic.
    pub fn new(tables: &Tables) -> Self {
        CngState {
            noise_seed: tables.scalar(Scalar::CngRandomSeedInitial),
            q_sid: tables.sid_initial_lsp,
            g_sid: 0,
            g_target: 0,
            saved_excitation_energy: (0, 0),
        }
    }

    /// The saved excitation energy (mantissa, exponent).
    ///
    /// # Panics
    ///
    /// Does not panic.
    pub fn saved_energy(&self) -> (i16, i16) {
        self.saved_excitation_energy
    }
}

/// The random parameters of one comfort-noise subframe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RandomParams {
    /// Integer pitch delay, 40..103.
    pub delay: i16,
    /// Fraction in thirds, -1..1.
    pub frac: i16,
    /// Pulse positions, tracks 0..3.
    pub positions: [usize; 4],
    /// Pulse signs (true = positive).
    pub signs: [bool; 4],
    /// Adaptive gain Ga before the solvability check, Q14.
    pub adaptive_gain: i16,
}

/// Draw the delay, pulses and adaptive gain of a subframe (3 draws).
///
/// # Panics
///
/// Does not panic.
pub fn draw_params(tables: &Tables, seed: &mut i16) -> RandomParams {
    let d0 = fixed::random(seed) as u16;
    let d1 = fixed::random(seed) as u16;
    let d2 = fixed::random(seed) as u16;
    let mut frac = (d0 & 3) as i16 - 1;
    if frac == 2 {
        frac = 0;
    }
    let delay = text::CNG_PITCH_DELAY_MIN + ((d0 >> 2) & 63) as i16;
    let i0 = usize::from((d0 >> 8) & 7);
    let s0 = (d0 >> 11) & 1 != 0;
    let i1 = usize::from((d0 >> 12) & 7);
    let s1 = (d0 >> 15) & 1 != 0;
    let i2 = usize::from(d1 & 7);
    let s2 = (d1 >> 3) & 1 != 0;
    let jx = usize::from((d1 >> 4) & 1);
    let i3 = usize::from((d1 >> 5) & 7);
    let s3 = (d1 >> 8) & 1 != 0;
    let mask = tables.scalar(Scalar::CngAdaptiveGainMask) as u16;
    RandomParams {
        delay,
        frac,
        positions: [5 * i0, 5 * i1 + 1, 5 * i2 + 2, 5 * i3 + 3 + jx],
        signs: [s0, s1, s2, s3],
        adaptive_gain: (d2 & mask) as i16,
    }
}

/// Draw the 40 raw Gaussian samples, Q9: each the sum of 12 draws, shifted
/// right by 7.
///
/// # Panics
///
/// Does not panic.
///
/// # Examples
///
/// ```
/// use g729::cng::draw_gaussian;
///
/// let (mut first, mut second) = (11, 11);
/// // The same seed gives the same samples, and the seed advances.
/// assert_eq!(draw_gaussian(&mut first), draw_gaussian(&mut second));
/// assert_eq!(first, second);
/// assert_ne!(first, 11);
/// ```
pub fn draw_gaussian(seed: &mut i16) -> [i16; 40] {
    let mut out = [0i16; 40];
    for o in out.iter_mut() {
        let mut sum = 0i32;
        for _ in 0..GAUSS_DRAWS {
            sum += i32::from(fixed::random(seed));
        }
        *o = extract_l(sum >> 7);
    }
    out
}

/// Every step of the Gaussian scaling (clause B.4.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GaussianSteps {
    /// 2 x sum of squared raw samples (saturated).
    pub energy: i32,
    /// 1/sqrt(sum of squared raw samples), Q30.
    pub inverse_sqrt: i32,
    /// Its high part.
    pub inverse_sqrt_high: i16,
    /// Its low part.
    pub inverse_sqrt_low: i16,
    /// G_t sqrt(40) alpha / 2 with alpha = 0.5, Q3.
    pub gain_factor: i16,
    /// The product of the two, Q18.
    pub scale: i32,
    /// Left shift normalizing `scale`.
    pub normalization: i16,
    /// `scale` as a 16-bit mantissa.
    pub mantissa: i16,
    /// `normalization` - 14.
    pub final_shift: i16,
    /// Each sample times the mantissa, before the final shift.
    pub before_shift: [i16; 40],
    /// ex2(n), Q0.
    pub scaled: [i16; 40],
}

/// Scale the raw Gaussian samples to the target gain: ex2(n) has mean
/// energy (alpha G_t)^2 with alpha = 0.5 (clause B.4.4).
///
/// # Panics
///
/// Does not panic.
pub fn gaussian_steps(
    ops: &mut Ctx,
    tables: &Tables,
    raw: &[i16; 40],
    target: i16,
) -> GaussianSteps {
    let mut energy = 0i32;
    for &x in raw {
        energy = ops.l_mac(energy, x, x);
    }
    let half = ops.l_shr(energy, 1);
    let inverse_sqrt = ops.inverse_square_root(half);
    let (inverse_sqrt_high, inverse_sqrt_low) = ops.split_high_low(inverse_sqrt);
    let fraction = ops.mult_r(target, tables.scalar(Scalar::CngGaussianScaleFraction));
    let gain_factor = ops.add(target, fraction);
    let scale = ops.multiply_split_by_16(inverse_sqrt_high, inverse_sqrt_low, gain_factor);
    let normalization = norm_l(scale);
    let mantissa = extract_h(ops.l_shl(scale, normalization));
    let final_shift = ops.sub(normalization, 14);
    let mut before_shift = [0i16; 40];
    let mut scaled = [0i16; 40];
    for n in 0..40 {
        before_shift[n] = ops.mult_r(raw[n], mantissa);
        scaled[n] = ops.shr_r(before_shift[n], final_shift);
    }
    GaussianSteps {
        energy,
        inverse_sqrt,
        inverse_sqrt_high,
        inverse_sqrt_low,
        gain_factor,
        scale,
        normalization,
        mantissa,
        final_shift,
        before_shift,
        scaled,
    }
}

/// ex2(n) only.
///
/// # Panics
///
/// Does not panic.
pub fn scale_gaussian(ops: &mut Ctx, tables: &Tables, raw: &[i16; 40], target: i16) -> [i16; 40] {
    gaussian_steps(ops, tables, raw, target).scaled
}

/// The inputs of the fixed-gain computation for one subframe.
#[derive(Debug, Clone, Copy)]
pub struct CngSubframe<'a> {
    /// Ga ea(n) + ex2(n).
    pub mixed: &'a [i16; 40],
    /// ex2(n) alone.
    pub gaussian: &'a [i16; 40],
    /// Pulse positions.
    pub positions: &'a [usize; 4],
    /// Pulse signs (true = positive).
    pub signs: &'a [bool; 4],
    /// The drawn adaptive gain Ga, Q14.
    pub adaptive_gain: i16,
    /// The target gain G_t, Q3.
    pub target: i16,
}

/// The steps that apply when the adaptive gain is dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DroppedSteps {
    /// r for this case.
    pub root_shift: i16,
    /// I on ex2(n) alone, Q(-r).
    pub correlation_i: i16,
    /// (1 - alpha^2) K, Q2.
    pub k_times_k0: i32,
    /// 4 (1 - alpha^2) K, Q(1 - 2r).
    pub k_aligned: i32,
    /// I^2 + 4 (1 - alpha^2) K, Q(1 - 2r).
    pub discriminant: i32,
}

/// Every step of the fixed gain Gf (equations B.20 to B.23).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FixedGainSteps {
    /// Largest magnitude of the mixed excitation.
    pub max_abs: i16,
    /// s, the right shift before the energy.
    pub rescale_shift: i16,
    /// The mixed excitation shifted right by s.
    pub rescaled: [i16; 40],
    /// E_x, Q(1 - 2s).
    pub energy_ex: i32,
    /// I, Q(-s).
    pub correlation_i: i16,
    /// 10 G_t, truncated.
    pub k_factor: i16,
    /// K = 40 G_t^2, Q2.
    pub k_target_energy: i32,
    /// K, Q(1 - 2s).
    pub k_aligned: i32,
    /// K - E_x.
    pub k_minus_energy: i32,
    /// I, Q(-s - 1).
    pub correlation_i_halved: i16,
    /// I^2 + 4 (K - E_x), Q(-1 - 2s).
    pub discriminant: i32,
    /// s + 1.
    pub root_shift: i16,
    /// Present when the discriminant is negative (Ga dropped).
    pub dropped: Option<DroppedSteps>,
    /// Square root of the discriminant in use, Q(-r).
    pub sqrt: i16,
    /// sqrt - I.
    pub root_a: i16,
    /// -(I + sqrt).
    pub root_b: i16,
    /// The root of smaller magnitude (`root_a` on a tie).
    pub root_chosen: i16,
    /// Gf before bounding, Q0.
    pub unbounded: i16,
    /// Gf, Q0.
    pub fixed_gain: i16,
    /// Ga finally used, Q14.
    pub adaptive_gain: i16,
}

/// The right shift that brings a peak magnitude below 4096.
fn rescale_shift(peak: i16) -> i16 {
    let mut shift = 0;
    let mut m = peak;
    while m >= 4096 {
        m >>= 1;
        shift += 1;
    }
    shift
}

fn peak(x: &[i16; 40]) -> i16 {
    x.iter().map(|&v| abs_s(v)).max().unwrap_or(0)
}

/// I = sum over the pulses of sign x x(position), of x shifted right by s.
fn correlation(ops: &mut Ctx, x: &[i16; 40], shift: i16, sub: &CngSubframe<'_>) -> i16 {
    let mut i = 0i16;
    for k in 0..4 {
        let v = ops.shr(x[sub.positions[k]], shift);
        i = if sub.signs[k] {
            ops.add(i, v)
        } else {
            ops.sub(i, v)
        };
    }
    i
}

/// floor(sqrt(x)) of a non-negative 32-bit value (0 for a negative one).
fn isqrt(x: i32) -> i32 {
    if x <= 0 {
        return 0;
    }
    let x = x as u32;
    let mut res: u32 = 0;
    let mut bit: u32 = 1 << 30;
    let mut rem = x;
    while bit > rem {
        bit >>= 2;
    }
    while bit != 0 {
        if rem >= res + bit {
            rem -= res + bit;
            res = (res >> 1) + bit;
        } else {
            res >>= 1;
        }
        bit >>= 2;
    }
    res as i32
}

/// Equations B.20 to B.23: the fixed gain Gf such that Ga ea(n) + ex2(n) +
/// Gf ef(n) has the energy 40 G_t^2, the root of smaller magnitude, bounded.
/// When no real root exists, Ga is dropped and Gf solves for ex2(n) alone
/// with the energy (1 - alpha^2) 40 G_t^2.
///
/// # Panics
///
/// Panics if an entry of `sub.positions` is 40 or more (it indexes the
/// 40-sample subframe). The positions [`draw_params`] returns are always below
/// 40.
pub fn fixed_gain_steps(ops: &mut Ctx, tables: &Tables, sub: &CngSubframe<'_>) -> FixedGainSteps {
    let max_abs = peak(sub.mixed);
    let s = rescale_shift(max_abs);
    let mut rescaled = [0i16; 40];
    let mut energy_ex = 0i32;
    for (r, &m) in rescaled.iter_mut().zip(sub.mixed) {
        *r = ops.shr(m, s);
        energy_ex = ops.l_mac(energy_ex, *r, *r);
    }
    let correlation_i = correlation(ops, sub.mixed, s, sub);
    let p = ops.l_mult(sub.target, 10);
    let k_factor = extract_l(ops.l_shr(p, 4));
    let k_target_energy = ops.l_mult(k_factor, sub.target);
    let twice_s = ops.shl(s, 1);
    let sh = ops.add(1, twice_s);
    let k_aligned = ops.l_shr(k_target_energy, sh);
    let k_minus_energy = ops.l_sub(k_aligned, energy_ex);
    let correlation_i_halved = ops.shr(correlation_i, 1);
    let discriminant = ops.l_mac(k_minus_energy, correlation_i_halved, correlation_i_halved);
    let root_shift = ops.add(s, 1);
    let (dropped, disc, half_i, r, adaptive_gain) = if discriminant < 0 {
        let s2 = rescale_shift(peak(sub.gaussian));
        let r = ops.add(s2, 1);
        let ci = correlation(ops, sub.gaussian, r, sub);
        let k_times_k0 = ops.multiply_32_by_16(k_target_energy, tables.scalar(Scalar::CngK0));
        let twice_r = ops.shl(r, 1);
        let sh = ops.sub(twice_r, 1);
        let k_aligned = ops.l_shr(k_times_k0, sh);
        let disc = ops.l_mac(k_aligned, ci, ci);
        let d = DroppedSteps {
            root_shift: r,
            correlation_i: ci,
            k_times_k0,
            k_aligned,
            discriminant: disc,
        };
        (Some(d), disc, ci, r, 0)
    } else {
        (
            None,
            discriminant,
            correlation_i_halved,
            root_shift,
            sub.adaptive_gain,
        )
    };
    let sqrt = ops.sat16(2 * isqrt(disc >> 3));
    let root_a = ops.sub(sqrt, half_i);
    let sum = ops.add(half_i, sqrt);
    let root_b = ops.negate(sum);
    let root_chosen = if abs_s(root_a) <= abs_s(root_b) {
        root_a
    } else {
        root_b
    };
    let down = ops.sub(2, r);
    let unbounded = ops.shr_r(root_chosen, down);
    let limit = abs_s(tables.scalar(Scalar::CngFixedGainLimit));
    let floor = ops.negate(limit);
    let fixed_gain = unbounded.min(limit).max(floor);
    FixedGainSteps {
        max_abs,
        rescale_shift: s,
        rescaled,
        energy_ex,
        correlation_i,
        k_factor,
        k_target_energy,
        k_aligned,
        k_minus_energy,
        correlation_i_halved,
        discriminant,
        root_shift,
        dropped,
        sqrt,
        root_a,
        root_b,
        root_chosen,
        unbounded,
        fixed_gain,
        adaptive_gain,
    }
}

/// Every step of the recovery of a lost first SID gain (clauses B.4.2.1 and
/// B.4.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoverySteps {
    /// The saved energy, mantissa x 2^exponent, saturated (Q1).
    pub value: i32,
    /// Its high part.
    pub high: i16,
    /// Its low part.
    pub low: i16,
    /// The energy per sample, value x 410/32768.
    pub per_sample: i32,
    /// log2 integer part.
    pub log2_integer: i16,
    /// log2 fraction, Q15.
    pub log2_fraction: i16,
    /// log2 in Q10.
    pub log2_energy: i16,
    /// The SID energy index.
    pub index: u16,
}

/// Quantize the saved excitation energy to a SID energy index (clause
/// B.4.2.1): one level below -8 dB, 4 dB steps up to the knee, 2 dB steps
/// above, the top level above 65 dB, on log2 in Q10.
///
/// # Panics
///
/// Does not panic.
pub fn recovery_steps(ops: &mut Ctx, tables: &Tables, saved: (i16, i16)) -> RecoverySteps {
    let value = ops.l_shl(i32::from(saved.0), saved.1);
    let (high, low) = ops.split_high_low(value);
    let per_sample = ops.multiply_split_by_16(high, low, tables.sid_energy_scale[0]);
    let (log2_integer, log2_fraction) = ops.base2_log(per_sample, &tables.log2);
    let int_q10 = ops.shl(log2_integer, 10);
    // The fraction is rounded to Q10 (the oracle's round-3 grid and records).
    let frac_q10 = ops.shr_r(log2_fraction, 5);
    let x = ops.add(int_q10, frac_q10);
    // The knee is compared after the high-region offset is taken off x.
    let above_offset = ops.sub(x, tables.scalar(Scalar::SidEnergyQHighOffset));
    let index = if x < tables.scalar(Scalar::SidEnergyQLowThreshold) {
        0
    } else if x > tables.scalar(Scalar::SidEnergyQHighThreshold) {
        31
    } else if above_offset < tables.scalar(Scalar::SidEnergyQKnee) {
        let d = ops.add(x, tables.scalar(Scalar::SidEnergyQLowOffset));
        let p = ops.l_mult(d, tables.scalar(Scalar::SidEnergyQLowStep));
        extract_h(p)
    } else {
        let d = ops.sub(x, tables.scalar(Scalar::SidEnergyQHighOffset));
        let p = ops.l_mult(d, tables.scalar(Scalar::SidEnergyQHighStep));
        let q = ops.l_shr(p, 2);
        ops.sub(extract_h(q), 1)
    };
    RecoverySteps {
        value,
        high,
        low,
        per_sample,
        log2_integer,
        log2_fraction,
        log2_energy: x,
        index: index.clamp(0, 31) as u16,
    }
}

/// The SID energy index of the saved excitation energy.
///
/// # Panics
///
/// Does not panic.
pub fn quantize_energy(ops: &mut Ctx, tables: &Tables, saved: (i16, i16)) -> u16 {
    recovery_steps(ops, tables, saved).index
}

/// The energy of a frame's excitation as (mantissa, exponent).
///
/// # Panics
///
/// Does not panic.
pub fn frame_energy(ops: &mut Ctx, exc: &[i16]) -> (i16, i16) {
    let mut l = 0i32;
    for &x in exc {
        l = ops.l_mac(l, x, x);
    }
    let n = norm_l(l);
    let m = ops.l_shl(l, n);
    (ops.round(m), 16 - n)
}

/// Decode the SID LSF vector (clause B.4.2.2) and update the memory.
///
/// # Panics
///
/// Does not panic.
pub fn decode_sid_lsf(
    ops: &mut Ctx,
    tables: &Tables,
    st: &mut lsp::LsfQuantizerMemory,
    sid: &SidParams,
) -> [i16; 10] {
    let sw = usize::from(sid.switch & 1);
    let r1 = &tables.lsp_cb1[(tables.sid_cb1_subset[usize::from(sid.stage1 & 31)] as usize) & 127];
    let ra =
        &tables.lsp_cb2[(tables.sid_cb2_subset[0][usize::from(sid.stage2 & 15)] as usize) & 31];
    let rb =
        &tables.lsp_cb2[(tables.sid_cb2_subset[1][usize::from(sid.stage2 & 15)] as usize) & 31];
    let mut l = [0i16; 10];
    for i in 0..10 {
        l[i] = ops.add(r1[i], if i < 5 { ra[i] } else { rb[i] });
    }
    lsp::enforce_spacing(ops, &mut l, text::SID_LSF_MIN_DISTANCE);
    let w = lsp::ma_prediction(
        ops,
        &l,
        st.past_output_rows(),
        &tables.sid_ma[sw],
        &tables.sid_ma_sum[sw],
    );
    let w = lsp::order_and_bound(ops, tables, w);
    st.remember_output(l);
    w
}

/// Bookkeeping after an active frame: the generator restarts, and a good
/// frame's excitation energy is saved.
pub(crate) fn after_active_frame(decoder: &mut Decoder<'_>, erased: bool, _omega_hat: &[i16; 10]) {
    decoder.comfort_noise.noise_seed = decoder.tables.scalar(Scalar::CngRandomSeedInitial);
    if !erased {
        let energy = frame_energy(&mut decoder.ops, &decoder.u_buffer[adaptive::PAST..]);
        decoder.comfort_noise.saved_excitation_energy = energy;
    }
}

impl Decoder<'_> {
    /// Decode a non-active frame (clauses B.4.4 and B.4.5): `sid` for a SID
    /// frame, `None` for an untransmitted one; `erased` when it stands for
    /// an erased frame.
    pub(crate) fn decode_comfort_noise_frame(
        &mut self,
        sid: Option<SidParams>,
        erased: bool,
        out: &mut [i16; FRAME_SAMPLES],
    ) {
        let tables = self.tables;
        if let Some(fields) = sid {
            let omega_sid = decode_sid_lsf(&mut self.ops, tables, &mut self.lsf_quantizer, &fields);
            self.comfort_noise.q_sid = lsp::lsf_to_lsp(&mut self.ops, tables, &omega_sid);
            self.comfort_noise.g_sid = formula::SID_GAIN[usize::from(fields.energy & 31)];
        } else if self.last_frame_active {
            // The first SID frame of the period was lost (clause B.4.5).
            let energy_index = quantize_energy(
                &mut self.ops,
                tables,
                self.comfort_noise.saved_excitation_energy,
            );
            self.comfort_noise.g_sid = formula::SID_GAIN[usize::from(energy_index)];
        }
        let state = &self.comfort_noise;
        let (g_previous, g_sid) = (state.g_target, state.g_sid);
        self.comfort_noise.g_target =
            smooth_target(&mut self.ops, g_previous, g_sid, self.last_frame_active);
        let q_current = self.comfort_noise.q_sid;
        let q_first = lsp::interpolate(&mut self.ops, &self.q_previous, &q_current);
        let a_hat = [
            lpc::lsp_to_lp(&mut self.ops, &q_first),
            lpc::lsp_to_lp(&mut self.ops, &q_current),
        ];
        self.q_previous = q_current;
        // The excitation of both subframes is built before either is
        // synthesized: when the first subframe's synthesis saturates, the
        // division of u(n) by 4 also scales the second subframe's excitation
        // (the oracle's round-3 stream G03).
        for subframe in 0..2 {
            let start = adaptive::PAST + 40 * subframe;
            let excitation = self.comfort_noise_excitation(start);
            self.u_buffer[start..start + 40].copy_from_slice(&excitation);
        }
        for (subframe, a_subframe) in a_hat.iter().enumerate() {
            let start = adaptive::PAST + 40 * subframe;
            let samples = self.finish_subframe(a_subframe, start, None);
            out[40 * subframe..40 * subframe + 40].copy_from_slice(&samples);
        }
        if !erased {
            let energy = frame_energy(&mut self.ops, &self.u_buffer[adaptive::PAST..]);
            self.comfort_noise.saved_excitation_energy = energy;
        }
        self.u_buffer.copy_within(FRAME_SAMPLES.., 0);
        self.beta = text::PITCH_SHARPENING_MIN;
        self.last_frame_active = false;
    }

    /// The comfort-noise excitation of the subframe starting at `start`
    /// (clause B.4.4).
    fn comfort_noise_excitation(&mut self, start: usize) -> [i16; 40] {
        let tables = self.tables;
        let g_target = self.comfort_noise.g_target;
        let drawn = draw_params(tables, &mut self.comfort_noise.noise_seed);
        let raw = draw_gaussian(&mut self.comfort_noise.noise_seed);
        if g_target == 0 {
            return [0; 40];
        }
        let ex2 = scale_gaussian(&mut self.ops, tables, &raw, g_target);
        adaptive::adaptive_vector(
            &mut self.ops,
            tables,
            &mut self.u_buffer,
            start,
            drawn.delay,
            drawn.frac,
        );
        let mut ea = [0i16; 40];
        ea.copy_from_slice(&self.u_buffer[start..start + 40]);
        let mixed = compose(&mut self.ops, &ea, drawn.adaptive_gain, &ex2);
        let inputs = CngSubframe {
            mixed: &mixed,
            gaussian: &ex2,
            positions: &drawn.positions,
            signs: &drawn.signs,
            adaptive_gain: drawn.adaptive_gain,
            target: g_target,
        };
        let solved = fixed_gain_steps(&mut self.ops, tables, &inputs);
        let mut ex = if solved.dropped.is_some() { ex2 } else { mixed };
        add_pulses(
            &mut self.ops,
            &mut ex,
            &drawn.positions,
            &drawn.signs,
            solved.fixed_gain,
        );
        ex
    }
}

/// Equation (B.19): the target gain, Q3: the SID gain after an active frame,
/// else 7/8 of the previous target plus 1/8 of the SID gain, each term
/// rounded.
///
/// # Panics
///
/// Does not panic.
///
/// # Examples
///
/// ```
/// use g729::basic_op::Ctx;
/// use g729::cng::smooth_target;
///
/// let mut ops = Ctx::default();
/// // Right after an active frame, the target is the SID gain itself.
/// assert_eq!(smooth_target(&mut ops, 100, 80, true), 80);
/// // A steady SID gain keeps a target already equal to it.
/// assert_eq!(smooth_target(&mut ops, 80, 80, false), 80);
/// ```
pub fn smooth_target(ops: &mut Ctx, g_previous: i16, g_sid: i16, after_active_frame: bool) -> i16 {
    if after_active_frame {
        return g_sid;
    }
    let weighted = [
        (g_previous, text::CNG_GAIN_SMOOTHING_OLD),
        (g_sid, text::CNG_GAIN_SMOOTHING_NEW),
    ];
    weighted.iter().fold(0, |sum, &(gain, weight)| {
        let term = ops.mult_r(gain, weight);
        ops.add(sum, term)
    })
}

/// round(Ga ea(n)) + ex2(n), Ga in Q14: the excitation before the pulses.
///
/// # Panics
///
/// Does not panic.
///
/// # Examples
///
/// ```
/// use g729::basic_op::Ctx;
/// use g729::cng::compose;
///
/// let mut ops = Ctx::default();
/// let ex2 = [3i16; 40];
/// // With Ga = 0 the adaptive part vanishes and ex2(n) is returned.
/// assert_eq!(compose(&mut ops, &[1000; 40], 0, &ex2), ex2);
/// ```
pub fn compose(ops: &mut Ctx, ea: &[i16; 40], ga: i16, ex2: &[i16; 40]) -> [i16; 40] {
    core::array::from_fn(|n| {
        let product = ops.l_mult(ea[n], ga);
        let doubled = ops.l_shl(product, 1);
        let adaptive_part = ops.round(doubled);
        ops.add(adaptive_part, ex2[n])
    })
}

/// Add the four pulses of amplitude Gf (equation (B.23)).
///
/// # Panics
///
/// Panics if an entry of `positions` is 40 or more (it indexes `x`). The
/// positions [`draw_params`] returns are always below 40.
///
/// # Examples
///
/// ```
/// use g729::basic_op::Ctx;
/// use g729::cng::add_pulses;
///
/// let mut ops = Ctx::default();
/// let mut x = [0i16; 40];
/// add_pulses(&mut ops, &mut x, &[0, 6, 12, 18], &[true, false, true, false], 5);
/// assert_eq!((x[0], x[6], x[12], x[18]), (5, -5, 5, -5));
/// assert_eq!(x.iter().filter(|&&v| v != 0).count(), 4);
/// ```
pub fn add_pulses(
    ops: &mut Ctx,
    x: &mut [i16; 40],
    positions: &[usize; 4],
    signs: &[bool; 4],
    gf: i16,
) {
    for k in 0..4 {
        let p = positions[k];
        x[p] = if signs[k] {
            ops.add(x[p], gf)
        } else {
            ops.sub(x[p], gf)
        };
    }
}
