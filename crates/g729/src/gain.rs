// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! Gains: the MA-predicted fixed-codebook gain of G.729 clause 3.9.1
//! (equations (66) to (71)), decoding of the two-stage conjugate codebook
//! (clauses 3.9.2, 3.9.3 and 4.1.5, equations (73) and (74)), the
//! predictor-memory update of equation (72), the erased-frame attenuation of
//! clauses 4.4.2 and 4.4.3 (equations (93) to (95)), and the pitch-sharpening
//! factor of equation (47).

use crate::basic_op::{Ctx, extract_h, extract_l};
use crate::tables::{Scalar, Tables, formula, text};

/// The two decoded gains.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gains {
    /// Adaptive-codebook gain, Q14.
    pub gp: i16,
    /// Fixed-codebook gain, Q1.
    pub gc: i16,
}

/// The gain decoder's memory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GainState {
    /// Past quantized prediction errors U, most recent first (Q10 dB).
    mem: [i16; 4],
    past_gp: i16,
    past_gc: i16,
}

impl Default for GainState {
    fn default() -> Self {
        Self::new()
    }
}

/// Equation (47): beta, the previous quantized pitch gain bounded below by
/// 0.2 and above by the user-supplied upper bound.
///
/// # Panics
///
/// Does not panic.
pub fn sharpening(tables: &Tables, gp: i16) -> i16 {
    // Written without `clamp`, which panics on a lower bound above the upper
    // one; a user-supplied table must not be able to abort the decoder.
    gp.min(tables.scalar(Scalar::PitchSharpeningMax))
        .max(text::PITCH_SHARPENING_MIN)
}

/// The predicted fixed-codebook gain g'_c as (mantissa, Q exponent), from
/// the energy of the codevector and the predictor memory.
///
/// # Panics
///
/// Does not panic.
pub fn predict(ops: &mut Ctx, tables: &Tables, code: &[i16; 40], mem: &[i16; 4]) -> (i16, i16) {
    let mut ener = 0i32;
    for &x in code {
        ener = ops.l_mac(ener, x, x);
    }
    let (e, f) = ops.base2_log(ener, &tables.log2);
    let mut l = ops.multiply_split_by_16(e, f, tables.scalar(Scalar::GainPredictionLogScale));
    l = ops.l_mac(
        l,
        tables.scalar(Scalar::GainPredictionMeanEnergyMantissa),
        tables.scalar(Scalar::GainPredictionMeanEnergyMultiplier),
    );
    l = ops.l_shl(l, 10);
    for (&b, &u) in formula::GAIN_PREDICTION_COEFFICIENTS.iter().zip(mem) {
        l = ops.l_mac(l, b, u);
    }
    let g = extract_h(l);
    let l = ops.l_mult(g, tables.scalar(Scalar::GainPredictionDbToLog2));
    let l = ops.l_shr(l, 8);
    let (ex, fr) = ops.split_high_low(l);
    let mantissa = extract_l(ops.base2_power(14, fr));
    (mantissa, ops.sub(14, ex))
}

impl GainState {
    /// Initial state (Table 9: U = -14 dB).
    ///
    /// # Panics
    ///
    /// Does not panic.
    pub fn new() -> Self {
        GainState {
            mem: formula::GAIN_PREDICTOR_INITIAL_MEMORY,
            past_gp: 0,
            past_gc: 0,
        }
    }

    /// The predictor memory, most recent first.
    ///
    /// # Panics
    ///
    /// Does not panic.
    pub fn memory(&self) -> &[i16; 4] {
        &self.mem
    }

    /// Replace the predictor memory.
    ///
    /// # Panics
    ///
    /// Does not panic.
    pub fn set_memory(&mut self, m: &[i16; 4]) {
        self.mem = *m;
    }

    fn push(&mut self, u: i16) {
        self.mem.copy_within(0..3, 1);
        self.mem[0] = u;
    }

    /// Decode received gain indices GA, GB for codevector `code`.
    ///
    /// Only the 3 low bits of `ga` and the 4 low bits of `gb` are read.
    ///
    /// # Panics
    ///
    /// Does not panic.
    pub fn decode(
        &mut self,
        ops: &mut Ctx,
        tables: &Tables,
        ga: u16,
        gb: u16,
        code: &[i16; 40],
    ) -> Gains {
        let ra = (tables.map_ga[usize::from(ga & 7)] as usize) & 7;
        let rb = (tables.map_gb[usize::from(gb & 15)] as usize) & 15;
        let (g0, exp) = predict(ops, tables, code, &self.mem);
        let gp = ops.add(tables.gain_ga[ra][0], tables.gain_gb[rb][0]);
        // gamma (Q13) held in 32 bits: it can exceed 16 bits.
        let gamma = ops.l_add(
            i32::from(tables.gain_ga[ra][1]),
            i32::from(tables.gain_gb[rb][1]),
        );
        let gamma_q12 = extract_l(ops.l_shr(gamma, 1));
        let l = ops.l_mult(g0, gamma_q12);
        let sh = ops.sub(exp, 4);
        let l = ops.l_shr(l, sh);
        let gc = extract_h(l);
        // Equation (72): U = 20 log10(gamma), via log2 truncated to Q13.
        let (e, f) = ops.base2_log(gamma, &tables.log2);
        let e13 = ops.sub(e, 13);
        let l = ops.join_high_low(e13, f);
        let l = ops.l_shl(l, 13);
        let u = ops.mult(extract_h(l), tables.scalar(Scalar::GainUpdateLog2ToDb));
        self.push(u);
        self.past_gp = gp;
        self.past_gc = gc;
        Gains { gp, gc }
    }

    /// The gains of an erased subframe (clauses 4.4.2 and 4.4.3).
    ///
    /// # Panics
    ///
    /// Does not panic.
    pub fn conceal(&mut self, ops: &mut Ctx, tables: &Tables) -> Gains {
        let mut gp = ops.mult(self.past_gp, text::ERASURE_PITCH_GAIN_ATTENUATION);
        let limit = tables.scalar(Scalar::ErasurePitchGainLimit);
        if gp > limit {
            gp = limit;
        }
        let gc = ops.mult(
            self.past_gc,
            tables.scalar(Scalar::ErasureFixedGainAttenuation),
        );
        let mut sum = 0i32;
        for &u in &self.mem {
            sum = ops.l_add(sum, i32::from(u));
        }
        let mut av = extract_l(ops.l_shr(sum, 2));
        av = ops.sub(av, text::ERASURE_GAIN_MEMORY_OFFSET);
        if av < text::ERASURE_GAIN_MEMORY_FLOOR {
            av = text::ERASURE_GAIN_MEMORY_FLOOR;
        }
        self.push(av);
        self.past_gp = gp;
        self.past_gc = gc;
        Gains { gp, gc }
    }
}
