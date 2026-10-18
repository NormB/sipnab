// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! LSP decoding: G.729 clause 3.2.4 (two-stage codebook, rearrangement,
//! switched MA prediction, stability), clause 4.1.1, clause 4.4.1 (repetition
//! on an erased frame, equation (92)), the LSF-to-LSP cosine conversion of
//! clauses 3.2.4/3.2.6, and the subframe interpolation of clause 3.2.5
//! (equation (24)).

use crate::basic_op::{Ctx, extract_h, extract_l, l_deposit_h};
use crate::tables::{Scalar, Tables, formula, text};

/// The LSF quantizer's memory (clause 3.2.4) and what concealment needs
/// (clause 4.4.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LsfQuantizerMemory {
    /// l^(m-1) .. l^(m-4): past quantizer outputs, most recent first (Q13).
    l_hat_past: [[i16; 10]; 4],
    /// The switched predictor L0 of the last good frame.
    predictor_last_good: usize,
    /// omega^ of the last good frame (Q13).
    omega_last_good: [i16; 10],
}

impl LsfQuantizerMemory {
    /// Initial state (Table 9: l_i = i pi/11).
    ///
    /// # Panics
    ///
    /// Does not panic.
    pub fn new(_tables: &Tables) -> Self {
        let start = formula::LSP_QUANTIZER_INITIAL_MEMORY;
        LsfQuantizerMemory {
            l_hat_past: [start; 4],
            predictor_last_good: 0,
            omega_last_good: start,
        }
    }

    /// The four past quantizer outputs, most recent first, flattened.
    ///
    /// # Panics
    ///
    /// Does not panic.
    pub fn past_outputs(&self) -> [i16; 40] {
        let flat = self.l_hat_past.as_flattened();
        core::array::from_fn(|n| flat[n])
    }

    /// Replace the past outputs (when a non-active frame updated them).
    ///
    /// # Panics
    ///
    /// Does not panic.
    pub fn replace_past_outputs(&mut self, flat: &[i16; 40]) {
        self.l_hat_past.as_flattened_mut().copy_from_slice(flat);
    }

    /// The past outputs as rows, most recent first.
    #[cfg(feature = "annex-b")]
    pub(crate) fn past_output_rows(&self) -> &[[i16; 10]; 4] {
        &self.l_hat_past
    }

    /// Make `l_hat` the most recent past output.
    pub(crate) fn remember_output(&mut self, l_hat: [i16; 10]) {
        self.l_hat_past.rotate_right(1);
        self.l_hat_past[0] = l_hat;
    }

    /// Decode a frame's LSF vector omega^ (Q13) from (L0, L1, L2, L3), or,
    /// for an erased frame (`None`), repeat the last good one.
    ///
    /// Each index is masked to its field width (L0 1 bit, L1 7, L2 and L3 5).
    ///
    /// # Panics
    ///
    /// Does not panic.
    pub fn decode_frame(
        &mut self,
        ops: &mut Ctx,
        tables: &Tables,
        indices: Option<[u16; 4]>,
    ) -> [i16; 10] {
        let Some([l0, l1, l2, l3]) = indices else {
            let predictor = self.predictor_last_good;
            let omega_hat = self.omega_last_good;
            let weights = &tables.lsp_ma[predictor];
            let inverse = &tables.lsp_ma_sum_inv[predictor];
            let l_hat = invert_ma_prediction(ops, &omega_hat, &self.l_hat_past, weights, inverse);
            self.remember_output(l_hat);
            return omega_hat;
        };
        let predictor = usize::from(l0 & 1);
        let first_stage = &tables.lsp_cb1[usize::from(l1 & 127)];
        let lower = &tables.lsp_cb2[usize::from(l2 & 31)];
        let upper = &tables.lsp_cb2[usize::from(l3 & 31)];
        let mut l_hat: [i16; 10] = core::array::from_fn(|i| {
            let second_stage = if i < 5 { lower[i] } else { upper[i] };
            ops.add(first_stage[i], second_stage)
        });
        for spacing in [text::LSF_EXPANSION_GAP_1, text::LSF_EXPANSION_GAP_2] {
            enforce_spacing(ops, &mut l_hat, spacing);
        }
        let weights = &tables.lsp_ma[predictor];
        let complement = &tables.lsp_ma_sum[predictor];
        let predicted = ma_prediction(ops, &l_hat, &self.l_hat_past, weights, complement);
        let omega_hat = order_and_bound(ops, tables, predicted);
        self.remember_output(l_hat);
        self.predictor_last_good = predictor;
        self.omega_last_good = omega_hat;
        omega_hat
    }
}

/// Move one adjacent pair apart so that `upper` - `lower` >= `spacing`,
/// each by half the shortfall (clause 3.2.4).
fn spread_pair(ops: &mut Ctx, lower: &mut i16, upper: &mut i16, spacing: i16) {
    let gap = ops.sub(*lower, *upper);
    let shortfall = ops.add(gap, spacing);
    if shortfall > 0 {
        let half = shortfall >> 1;
        *lower = ops.sub(*lower, half);
        *upper = ops.add(*upper, half);
    }
}

/// Clause 3.2.4 rearrangement: adjacent coefficients at least `spacing`
/// apart, pairs taken left to right (each pair sees the previous update).
///
/// # Panics
///
/// Does not panic.
///
/// # Examples
///
/// ```
/// use g729::basic_op::Ctx;
///
/// let mut l_hat = [0, 100, 104, 200, 300, 400, 500, 600, 700, 800];
/// g729::lsp::enforce_spacing(&mut Ctx::default(), &mut l_hat, 10);
/// // 100 and 104 are 4 apart; each moves by half of the 6 missing.
/// assert_eq!(l_hat, [0, 97, 107, 200, 300, 400, 500, 600, 700, 800]);
/// ```
pub fn enforce_spacing(ops: &mut Ctx, l_hat: &mut [i16; 10], spacing: i16) {
    for boundary in 1..l_hat.len() {
        let (head, tail) = l_hat.split_at_mut(boundary);
        if let (Some(lower), Some(upper)) = (head.last_mut(), tail.first_mut()) {
            spread_pair(ops, lower, upper, spacing);
        }
    }
}

/// Equation (20): omega^_i = (1 - sum p) l^_i + sum over k of p_k l^(m-k)_i,
/// the current term first, then the past terms in order of age.
///
/// # Panics
///
/// Does not panic.
pub fn ma_prediction(
    ops: &mut Ctx,
    l_hat: &[i16; 10],
    l_hat_past: &[[i16; 10]; 4],
    weights: &[[i16; 10]; 4],
    complement: &[i16; 10],
) -> [i16; 10] {
    core::array::from_fn(|i| {
        let current = ops.l_mult(l_hat[i], complement[i]);
        let total = l_hat_past
            .iter()
            .zip(weights)
            .fold(current, |sum, (past, p)| ops.l_mac(sum, past[i], p[i]));
        extract_h(total)
    })
}

/// Equation (92): the quantizer output l^ that gives `omega_hat` from the
/// past outputs: (omega^ - sum p l^past) / (1 - sum p).
///
/// # Panics
///
/// Does not panic.
pub fn invert_ma_prediction(
    ops: &mut Ctx,
    omega_hat: &[i16; 10],
    l_hat_past: &[[i16; 10]; 4],
    weights: &[[i16; 10]; 4],
    inverse_complement: &[i16; 10],
) -> [i16; 10] {
    core::array::from_fn(|i| {
        let start = l_deposit_h(omega_hat[i]);
        let residual = l_hat_past
            .iter()
            .zip(weights)
            .fold(start, |sum, (past, p)| ops.l_msu(sum, past[i], p[i]));
        let scaled = ops.l_mult(extract_h(residual), inverse_complement[i]);
        extract_h(ops.l_shl(scaled, 3))
    })
}

/// Clause 3.2.4 stability: increasing order, a lowest first value, a minimum
/// distance between neighbors (left to right), a highest last value.
///
/// # Panics
///
/// Does not panic.
pub fn order_and_bound(ops: &mut Ctx, tables: &Tables, mut omega: [i16; 10]) -> [i16; 10] {
    omega.sort_unstable();
    omega[0] = omega[0].max(tables.scalar(Scalar::LsfStabilityLowLimit));
    let distance = tables.scalar(Scalar::LsfStabilityMinDistance);
    for boundary in 1..omega.len() {
        if ops.sub(omega[boundary], omega[boundary - 1]) < distance {
            omega[boundary] = ops.add(omega[boundary - 1], distance);
        }
    }
    omega[9] = omega[9].min(tables.scalar(Scalar::LsfStabilityHighLimit));
    omega
}

/// LSF (Q13 radians) to LSP (Q15 cosine) by table lookup and interpolation.
///
/// # Panics
///
/// Does not panic.
pub fn lsf_to_lsp(ops: &mut Ctx, tables: &Tables, lsf: &[i16; 10]) -> [i16; 10] {
    let scale = tables.scalar(Scalar::LsfToLspFrequencyScale);
    let mut out = [0i16; 10];
    for i in 0..10 {
        let freq = ops.mult(lsf[i], scale);
        let ind = usize::from((freq >> 8) as u16 & 0xff).min(63);
        let off = freq & 0xff;
        let p = ops.l_mult(formula::LSP_COSINE_SLOPE[ind], off);
        let p = ops.l_shr(p, 13);
        out[i] = ops.add(formula::LSP_COSINE[ind], extract_l(p));
    }
    out
}

/// Equation (24): the subframe-1 LSP vector, halfway between the previous
/// and the current frame's.
///
/// # Panics
///
/// Does not panic.
///
/// # Examples
///
/// ```
/// use g729::basic_op::Ctx;
///
/// let q = g729::lsp::interpolate(&mut Ctx::default(), &[1000; 10], &[3000; 10]);
/// assert_eq!(q, [2000; 10]);
/// ```
pub fn interpolate(ops: &mut Ctx, prev: &[i16; 10], cur: &[i16; 10]) -> [i16; 10] {
    let mut out = [0i16; 10];
    for i in 0..10 {
        out[i] = ops.add(prev[i] >> 1, cur[i] >> 1);
    }
    out
}
