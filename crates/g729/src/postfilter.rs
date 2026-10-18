// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! The Annex A adaptive postfilter (G.729 clause A.4.2): the residual through
//! A(z/gamma_n) (equation (79)), the integer-delay long-term postfilter of
//! clause A.4.2.1 (equations (A.11), (80) to (83)), the tilt compensation of
//! clause A.4.2.3 (equations (A.13) and (A.14)), applied before the
//! short-term synthesis filter 1/A(z/gamma_d) of clause A.4.2.2 (equation
//! (A.12)), and the adaptive gain control of clause A.4.2.4 (equation (A.15)
//! and g(n) = 0.9 g(n-1) + 0.1 G).
//!
//! The long-term analysis works on the residual divided by 4, the energies
//! start from 1, and the tilt correlations are taken unnormalized; these
//! fixed-point choices are not in the text and were established from the
//! oracle's traces.

use crate::basic_op::{Ctx, div_s, extract_h, norm_l};
use crate::lpc::weight;
use crate::synth::{impulse_response, synthesize};
use crate::tables::{Tables, text};

/// The largest pitch delay: how much past residual the long-term search sees.
const MAX_DELAY: usize = text::PITCH_DELAY_MAX as usize;
/// Length of the truncated impulse response h_f(n) of equation (A.14).
const H_F_LENGTH: usize = text::TILT_IMPULSE_RESPONSE_LENGTH as usize;

/// Every intermediate signal of one subframe (for the stage tests).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostfilterTrace {
    /// r^(n): the residual through A(z/gamma_n) (equation (79)).
    pub r_hat: [i16; 40],
    /// Whether the long-term postfilter was applied.
    pub long_term_on: bool,
    /// The selected delay T (`None` in a non-active frame).
    pub long_term_delay: Option<i16>,
    /// 1/(1 + gamma_p g_l), Q15, when on.
    pub weight_current: Option<i16>,
    /// gamma_p g_l/(1 + gamma_p g_l), Q15, when on.
    pub weight_delayed: Option<i16>,
    /// The long-term postfilter output.
    pub long_term_output: [i16; 40],
    /// The tilt factor of 1 - g z^-1 (equation (A.13)), Q15.
    pub tilt_factor: i16,
    /// The tilt-compensated signal.
    pub tilt_output: [i16; 40],
    /// The output of 1/A(z/gamma_d): sf(n).
    pub short_term_output: [i16; 40],
    /// (1 - alpha) G, Q12 (equation (A.15)); `None` when sf(n) has no energy.
    pub gain_target: Option<i16>,
    /// g(n) after the subframe, Q12.
    pub gain_end: i16,
    /// sf'(n), the postfilter output.
    pub output: [i16; 40],
}

/// The adaptive postfilter's memory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdaptivePostfilter {
    /// Past r^(n), oldest first.
    r_hat_history: [i16; MAX_DELAY],
    /// The last 10 samples of s^(n).
    s_hat_tail: [i16; 10],
    /// The last long-term output sample (the tilt filter's memory).
    last_long_term_sample: i16,
    /// The last 10 samples of sf(n).
    sf_tail: [i16; 10],
    /// g(n), Q12.
    g_agc: i16,
}

impl Default for AdaptivePostfilter {
    fn default() -> Self {
        Self::new()
    }
}

/// The long-term postfilter's choice for one subframe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LongTermChoice {
    /// The delay T searched (`None` when no search runs).
    delay: Option<i16>,
    /// (current, delayed) weights, when the filter is on.
    weights: Option<(i16, i16)>,
}

/// The inputs of one postfiltered subframe.
#[derive(Debug, Clone, Copy)]
pub struct PostfilterInput<'a> {
    /// a^_i of the subframe, Q12.
    pub a_hat: &'a [i16; 11],
    /// s^(n), the reconstructed speech.
    pub s_hat: &'a [i16; 40],
    /// The subframe's integer pitch delay, the center of the delay search.
    pub pitch_delay: i16,
    /// False in an Annex B non-active frame: no long-term postfilter.
    pub long_term: bool,
}

impl AdaptivePostfilter {
    /// Initial state: zero memories, g(-1) = 1.0 (clause 4.2.4).
    ///
    /// # Panics
    ///
    /// Does not panic.
    pub fn new() -> Self {
        AdaptivePostfilter {
            r_hat_history: [0; MAX_DELAY],
            s_hat_tail: [0; 10],
            last_long_term_sample: 0,
            sf_tail: [0; 10],
            g_agc: text::AGC_INITIAL_GAIN,
        }
    }

    /// Postfilter one subframe and report every stage.
    ///
    /// # Panics
    ///
    /// Does not panic.
    pub fn run_traced(
        &mut self,
        ops: &mut Ctx,
        _tables: &Tables,
        input: &PostfilterInput<'_>,
    ) -> PostfilterTrace {
        let numerator = weight(ops, input.a_hat, text::POSTFILTER_NUMERATOR_WEIGHT);
        let denominator = weight(ops, input.a_hat, text::POSTFILTER_DENOMINATOR_WEIGHT);
        let r_hat = self.inverse_filter(ops, &numerator, input.s_hat);

        let mut extended = [0i16; MAX_DELAY + 40];
        let (past, present) = extended.split_at_mut(MAX_DELAY);
        past.copy_from_slice(&self.r_hat_history);
        present.copy_from_slice(&r_hat);
        let choice = if input.long_term {
            long_term_analysis(ops, &extended, input.pitch_delay)
        } else {
            LongTermChoice {
                delay: None,
                weights: None,
            }
        };
        let long_term_output = match (choice.delay, choice.weights) {
            (Some(delay), Some((current, delayed))) => {
                let lag = delay as usize;
                core::array::from_fn(|n| {
                    let now = ops.mult(extended[MAX_DELAY + n], current);
                    let then = ops.mult(extended[MAX_DELAY + n - lag], delayed);
                    ops.add(now, then)
                })
            }
            _ => r_hat,
        };
        self.r_hat_history.copy_from_slice(&extended[40..]);

        let tilt_factor = tilt_factor_of(ops, &numerator, &denominator);
        let mut previous = self.last_long_term_sample;
        let tilt_output = long_term_output.map(|sample| {
            let leak = ops.mult(tilt_factor, previous);
            previous = sample;
            ops.sub(sample, leak)
        });
        self.last_long_term_sample = previous;
        let (short_term_output, _) = synthesize(ops, &denominator, &tilt_output, &self.sf_tail);
        self.sf_tail.copy_from_slice(&short_term_output[30..]);

        let gain_target = gain_target_of(ops, input.s_hat, &short_term_output);
        let output = match gain_target {
            None => {
                self.g_agc = 0;
                short_term_output
            }
            Some(target) => short_term_output.map(|sample| {
                let decayed = ops.mult(self.g_agc, text::AGC_FACTOR);
                self.g_agc = ops.add(decayed, target);
                let scaled = ops.l_mult(sample, self.g_agc);
                extract_h(ops.l_shl(scaled, 3))
            }),
        };
        self.s_hat_tail.copy_from_slice(&input.s_hat[30..]);

        PostfilterTrace {
            r_hat,
            long_term_on: choice.weights.is_some(),
            long_term_delay: choice.delay,
            weight_current: choice.weights.map(|w| w.0),
            weight_delayed: choice.weights.map(|w| w.1),
            long_term_output,
            tilt_factor,
            tilt_output,
            short_term_output,
            gain_target,
            gain_end: self.g_agc,
            output,
        }
    }

    /// Postfilter one subframe; the output only.
    ///
    /// # Panics
    ///
    /// Does not panic.
    pub fn run(
        &mut self,
        ops: &mut Ctx,
        tables: &Tables,
        input: &PostfilterInput<'_>,
    ) -> [i16; 40] {
        self.run_traced(ops, tables, input).output
    }

    /// Equation (79): r^(n) = s^(n) + sum gamma_n^i a^_i s^(n - i).
    fn inverse_filter(&self, ops: &mut Ctx, numerator: &[i16; 11], s_hat: &[i16; 40]) -> [i16; 40] {
        let mut history = [0i16; 50];
        history[..10].copy_from_slice(&self.s_hat_tail);
        history[10..].copy_from_slice(s_hat);
        core::array::from_fn(|n| {
            let now = 10 + n;
            let first = ops.l_mult(history[now], numerator[0]);
            let total = (1..11).fold(first, |sum, i| {
                ops.l_mac(sum, numerator[i], history[now - i])
            });
            let aligned = ops.l_shl(total, 3);
            ops.round(aligned)
        })
    }
}

/// Sum over n of `x`(n) `y`(n), from `start`.
fn correlation(ops: &mut Ctx, start: i32, x: &[i16], y: &[i16]) -> i32 {
    x.iter()
        .zip(y)
        .fold(start, |sum, (&p, &q)| ops.l_mac(sum, p, q))
}

/// Clause A.4.2.1: the delay in [Tcl - 3, Tcl + 3] (Tcl at most 140) whose
/// correlation of the residual divided by 4 is largest (the first on a tie),
/// and the weights of equation (A.11); no weights when the prediction gain is
/// below 3 dB (equation (82)). A negative correlation at the selected delay
/// is taken as 0, so the filter is off unless the delayed energy also rounds
/// to 0, and then on with the weights (1, 0) (the oracle's round-3 streams
/// G02 and G05).
fn long_term_analysis(
    ops: &mut Ctx,
    extended: &[i16; MAX_DELAY + 40],
    pitch_delay: i16,
) -> LongTermChoice {
    let reach = text::LONG_TERM_POSTFILTER_SEARCH_HALF_RANGE;
    // Tcl is bounded by 140 (clause A.4.2.1); the lower bound only keeps the
    // window inside the buffer for any input.
    let center = pitch_delay.clamp(reach + 1, 140);
    let highest = (center + reach).min(text::PITCH_DELAY_MAX);
    let lowest = highest - 2 * reach;
    let quarter: [i16; MAX_DELAY + 40] = extended.map(|sample| ops.shr(sample, 2));
    let present = &quarter[MAX_DELAY..];
    let at = |lag: i16| &quarter[MAX_DELAY - lag as usize..MAX_DELAY + 40 - lag as usize];
    let first = correlation(ops, 0, present, at(lowest));
    let (delay, best) = (lowest + 1..=highest).fold((lowest, first), |(best_lag, best), lag| {
        let value = correlation(ops, 0, present, at(lag));
        if value > best {
            (lag, value)
        } else {
            (best_lag, best)
        }
    });
    let cross = best.max(0);
    let delayed = at(delay);
    let delayed_energy = correlation(ops, 1, delayed, delayed);
    let current_energy = correlation(ops, 1, present, present);
    let shift = norm_l(cross.max(delayed_energy).max(current_energy));
    let mut to_16 = |value: i32| {
        let normalized = ops.l_shl(value, shift);
        ops.round(normalized)
    };
    let (cross_16, delayed_16, current_16) =
        (to_16(cross), to_16(delayed_energy), to_16(current_energy));
    let off = LongTermChoice {
        delay: Some(delay),
        weights: None,
    };
    // Equation (82): off when R'(T)^2 < 0.5 energy x energy.
    let squared = ops.l_mult(cross_16, cross_16);
    let product = ops.l_mult(delayed_16, current_16);
    if squared < ops.l_shr(product, 1) {
        return off;
    }
    // Equation (83): g_l bounded by 1.
    if cross_16 > delayed_16 {
        let weights = (
            text::LONG_TERM_POSTFILTER_UNIT_G0,
            text::LONG_TERM_POSTFILTER_UNIT_GL,
        );
        return LongTermChoice {
            delay: Some(delay),
            weights: Some(weights),
        };
    }
    let gamma_p_r = ops.mult(cross_16, text::LONG_TERM_POSTFILTER_GAMMA);
    let half_gamma_p_r = ops.shr(gamma_p_r, 1);
    let half_energy = ops.shr(delayed_16, 1);
    let denominator = ops.add(half_gamma_p_r, half_energy);
    let delayed_weight = div_s(half_gamma_p_r, denominator);
    let current_weight = ops.sub(i16::MAX, delayed_weight);
    LongTermChoice {
        delay: Some(delay),
        weights: Some((current_weight, delayed_weight)),
    }
}

/// Equation (A.14) and clause A.4.2.3: the tilt factor 0.8 r_h(1)/r_h(0) of
/// the truncated impulse response h_f of A(z/gamma_n)/A(z/gamma_d), or 0 when
/// r_h(1) is not positive.
fn tilt_factor_of(ops: &mut Ctx, numerator: &[i16; 11], denominator: &[i16; 11]) -> i16 {
    let mut excitation = [0i16; H_F_LENGTH];
    excitation[..11].copy_from_slice(numerator);
    let h_f = impulse_response(ops, denominator, &excitation);
    let r_h0 = correlation(ops, 0, &h_f, &h_f);
    let r_h1 = correlation(ops, 0, &h_f[..H_F_LENGTH - 1], &h_f[1..]);
    let (r_h0_16, r_h1_16) = (extract_h(r_h0), extract_h(r_h1));
    if r_h1_16 <= 0 {
        return 0;
    }
    let scaled = ops.mult(r_h1_16, text::TILT_COMPENSATION_FACTOR);
    div_s(scaled, r_h0_16)
}

/// Equation (A.15): (1 - alpha) sqrt(E(s^)/E(sf)) in Q12, the energies taken
/// on the signals divided by 4; `None` when sf(n) has no energy, else 0 when
/// s^(n) has none.
fn gain_target_of(ops: &mut Ctx, s_hat: &[i16; 40], sf: &[i16; 40]) -> Option<i16> {
    let mut energy = |signal: &[i16; 40]| {
        let quarter = signal.map(|sample| ops.shr(sample, 2));
        correlation(ops, 0, &quarter, &quarter)
    };
    let (energy_in, energy_out) = (energy(s_hat), energy(sf));
    if energy_out == 0 {
        return None;
    }
    if energy_in == 0 {
        return Some(0);
    }
    let shift_in = norm_l(energy_in);
    let in_normalized = ops.l_shl(energy_in, shift_in);
    let in_16 = ops.round(in_normalized);
    let shift_out = norm_l(energy_out);
    let out_normalized = ops.l_shl(energy_out, shift_out - 1);
    let out_16 = ops.round(out_normalized);
    let ratio = div_s(out_16, in_16);
    let widened = ops.l_shl(i32::from(ratio), 7);
    let aligned = ops.l_shr(widened, shift_out - shift_in - 1);
    let root = ops.inverse_square_root(aligned);
    let root_shifted = ops.l_shl(root, 9);
    let q12 = ops.round(root_shifted);
    Some(ops.mult(q12, text::AGC_FACTOR_COMPLEMENT))
}
