// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! Fixed (algebraic) codebook: decoding of the 13-bit position index and the
//! 4-bit sign index (G.729 clause 4.1.4, inverting equations (61) and (62)
//! over the tracks of Table 7), the codevector of equation (45), the pitch
//! sharpening of equation (48), and the random indices of an erased frame
//! (clause 4.4.4, equation (96)).

use crate::basic_op::{Ctx, extract_l};
use crate::tables::{Scalar, Tables, text};

/// Initial seed of the erasure random generator (clause 4.4.4).
pub const ERASURE_SEED: i16 = text::ERASURE_RANDOM_SEED_INITIAL;

/// Equation (96): seed = 31821 seed + 13849, kept to 16 bits (two's
/// complement wraparound, as the equation's generator is defined).
///
/// # Panics
///
/// Does not panic.
///
/// # Examples
///
/// ```
/// let mut seed = 0i16;
/// assert_eq!(g729::fixed::random(&mut seed), 13849);
/// assert_eq!(seed, 13849);
/// ```
pub fn random(seed: &mut i16) -> i16 {
    let next =
        i32::from(*seed) * i32::from(text::RANDOM_MULTIPLIER) + i32::from(text::RANDOM_INCREMENT);
    *seed = extract_l(next);
    *seed
}

/// Clause 4.4.4: the fixed-codebook index (13 LSBs of a random number) and
/// sign (4 LSBs of the next one) of an erased frame.
///
/// # Panics
///
/// Does not panic.
pub fn random_index(seed: &mut i16) -> (u16, u16) {
    let ops = random(seed) as u16 & 0x1fff;
    let s = random(seed) as u16 & 0xf;
    (ops, s)
}

/// Positions m0..m3 and signs s0..s3 (true = positive) of the four pulses.
///
/// Only the 13 low bits of `index` and the 4 low bits of `sign_index` are
/// read, so every position is below 40.
///
/// # Panics
///
/// Does not panic.
///
/// # Examples
///
/// ```
/// use g729::fixed::pulses;
///
/// assert_eq!(pulses(0, 0b1111), ([0, 1, 2, 3], [true; 4]));
/// assert_eq!(pulses(0x1fff, 0), ([35, 36, 37, 39], [false; 4]));
/// ```
pub fn pulses(index: u16, sign_index: u16) -> ([usize; 4], [bool; 4]) {
    let index = usize::from(index & 0x1fff);
    let track3 = index >> 9;
    let pos = [
        5 * (index & 7),
        5 * ((index >> 3) & 7) + 1,
        5 * ((index >> 6) & 7) + 2,
        5 * (track3 >> 1) + 3 + (track3 & 1),
    ];
    let sign = [
        sign_index & 1 != 0,
        sign_index & 2 != 0,
        sign_index & 4 != 0,
        sign_index & 8 != 0,
    ];
    (pos, sign)
}

/// Equation (45): the codevector (Q13).
///
/// # Panics
///
/// Panics if any of `pos` is 40 or more. [`pulses`] never returns such a
/// position.
pub fn codevector(tables: &Tables, pos: &[usize; 4], sign: &[bool; 4]) -> [i16; 40] {
    let mut code = [0i16; 40];
    for k in 0..4 {
        code[pos[k]] = if sign[k] {
            tables.scalar(Scalar::FixedCodebookPulsePositive)
        } else {
            text::FIXED_CODEBOOK_PULSE_NEGATIVE
        };
    }
    code
}

/// Equation (48): ops(n) += beta ops(n - T) for n >= T, when T < 40 (beta Q14).
///
/// A `t0` outside 1..40 leaves `code` unchanged.
///
/// # Panics
///
/// Does not panic.
pub fn sharpen(ops: &mut Ctx, code: &mut [i16; 40], t0: i16, beta: i16) {
    if !(1..40).contains(&t0) {
        return;
    }
    let t0 = t0 as usize;
    let b = ops.shl(beta, 1);
    for n in t0..40 {
        let p = ops.mult(code[n - t0], b);
        code[n] = ops.add(code[n], p);
    }
}
