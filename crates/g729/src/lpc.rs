// SPDX-License-Identifier: MIT OR Apache-2.0

//! LP filter coefficients: the LSP-to-LP conversion of G.729 clause 3.2.6
//! (the f1/f2 recursion and equations (25) and (26)), and the bandwidth
//! weighting a_i * gamma^i used by the postfilter (Annex A clause A.4.2.2,
//! equations (A.12) and (A.14)).

use crate::basic_op::{Ctx, extract_l};

/// 1.0 in Q24, the leading coefficient of F1(z) and F2(z).
const UNIT_Q24: i32 = 1 << 24;

/// One recursion stage of clause 3.2.6: multiply the polynomial `previous`
/// (degree `degree` - 1, coefficients f(0..), Q24) by 1 - 2 q z^-1 + z^-2,
/// keeping coefficients 0..=`degree`. Each new coefficient is built from the
/// previous stage only, so the order in which they are formed does not
/// matter.
fn next_stage(ops: &mut Ctx, previous: &[i32; 6], degree: usize, q: i16) -> [i32; 6] {
    let older = |j: usize| if j >= 2 { previous[j - 2] } else { 0 };
    let mut next = *previous;
    next[0] = UNIT_Q24;
    for j in 1..degree {
        let cross = ops.multiply_32_by_16(previous[j - 1], q);
        let doubled = ops.l_shl(cross, 1);
        let kept = ops.l_sub(previous[j], doubled);
        next[j] = ops.l_add(kept, older(j));
    }
    // The new highest coefficient: 2 f(degree - 2) - 2 q f(degree - 1).
    let cross = ops.multiply_32_by_16(previous[degree - 1], q);
    let twice_older = ops.l_shl(older(degree), 1);
    let doubled = ops.l_shl(cross, 1);
    next[degree] = ops.l_sub(twice_older, doubled);
    next
}

/// The coefficients f(0..5), Q24, of F1(z) (from q1, q3, .., q9) or F2(z)
/// (from q2, q4, .., q10): clause 3.2.6.
fn polynomial(ops: &mut Ctx, roots: [i16; 5]) -> [i32; 6] {
    let mut coefficients = [UNIT_Q24, 0, 0, 0, 0, 0];
    for (stage, &q) in roots.iter().enumerate() {
        coefficients = next_stage(ops, &coefficients, stage + 1, q);
    }
    coefficients
}

/// LSP vector q (Q15) to LP coefficients a_0..a_10 (Q12, a_0 = 4096):
/// equations (25) and (26).
///
/// # Panics
///
/// Does not panic.
pub fn lsp_to_lp(ops: &mut Ctx, q: &[i16; 10]) -> [i16; 11] {
    let odd: [i16; 5] = core::array::from_fn(|k| q[2 * k]);
    let even: [i16; 5] = core::array::from_fn(|k| q[2 * k + 1]);
    let f1 = polynomial(ops, odd);
    let f2 = polynomial(ops, even);
    // Equation (25): F'1 = F1 (1 + z^-1), F'2 = F2 (1 - z^-1).
    let f1_prime: [i32; 5] = core::array::from_fn(|k| ops.l_add(f1[k + 1], f1[k]));
    let f2_prime: [i32; 5] = core::array::from_fn(|k| ops.l_sub(f2[k + 1], f2[k]));
    // Equation (26): a_i = (f'1 + f'2)/2, a_(11-i) = (f'1 - f'2)/2.
    let mut a = [0i16; 11];
    a[0] = 4096;
    for (k, (&sum_term, &difference_term)) in f1_prime.iter().zip(&f2_prime).enumerate() {
        let half_sum = ops.l_add(sum_term, difference_term);
        let half_difference = ops.l_sub(sum_term, difference_term);
        a[k + 1] = extract_l(ops.l_shr_r(half_sum, 13));
        a[10 - k] = extract_l(ops.l_shr_r(half_difference, 13));
    }
    a
}

/// a_i gamma^i, i = 0..10 (Q12), the powers of gamma (Q15) formed by
/// repeated rounded multiplication.
///
/// # Panics
///
/// Does not panic.
pub fn weight(ops: &mut Ctx, a: &[i16; 11], gamma: i16) -> [i16; 11] {
    let mut power = gamma;
    core::array::from_fn(|i| {
        if i == 0 {
            return a[0];
        }
        let weighted = ops.mult_r(a[i], power);
        power = ops.mult_r(power, gamma);
        weighted
    })
}
