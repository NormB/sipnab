// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! Excitation and synthesis: u(n) = g_p v(n) + g_c ops(n) (G.729 equation
//! (75)), and the LP synthesis filter of clause 4.1.6 (equation (77)), which
//! reports whether its bit-exact arithmetic saturated (clause 5): the decoder
//! then divides the excitation memory by 4 and synthesizes again.

use crate::basic_op::Ctx;

/// Equation (75), Q0 output from v (Q0), ops (Q13), g_p (Q14) and g_c (Q1).
///
/// # Panics
///
/// Does not panic.
pub fn excitation(ops: &mut Ctx, v: &[i16; 40], code: &[i16; 40], gp: i16, gc: i16) -> [i16; 40] {
    let mut u = [0i16; 40];
    for n in 0..40 {
        let l = ops.l_mult(v[n], gp);
        let l = ops.l_mac(l, code[n], gc);
        let l = ops.l_shl(l, 1);
        u[n] = ops.round(l);
    }
    u
}

/// One sample of 1/A(z) (coefficients Q12).
fn synth_sample(ops: &mut Ctx, a: &[i16; 11], x: i16, past: &[i16]) -> i16 {
    let mut l = ops.l_mult(x, a[0]);
    for i in 1..11 {
        l = ops.l_msu(l, a[i], past[past.len() - i]);
    }
    let l = ops.l_shl(l, 3);
    ops.round(l)
}

/// Filter `x` through 1/A(z) from memory `mem` (the last 10 outputs, oldest
/// first). Returns the output and whether any operation saturated.
///
/// # Panics
///
/// Does not panic.
pub fn synthesize(
    ops: &mut Ctx,
    a: &[i16; 11],
    x: &[i16; 40],
    mem: &[i16; 10],
) -> ([i16; 40], bool) {
    let outer = ops.overflow;
    ops.overflow = false;
    let mut buf = [0i16; 50];
    buf[..10].copy_from_slice(mem);
    for n in 0..40 {
        buf[10 + n] = synth_sample(ops, a, x[n], &buf[..10 + n]);
    }
    let overflow = ops.overflow;
    ops.overflow = outer || overflow;
    let mut out = [0i16; 40];
    out.copy_from_slice(&buf[10..]);
    (out, overflow)
}

/// Filter `n` samples of `x` through 1/A(z) with zero memory (used for the
/// postfilter's impulse response).
///
/// # Panics
///
/// Panics if `N` is greater than 54.
pub fn impulse_response<const N: usize>(ops: &mut Ctx, a: &[i16; 11], x: &[i16; N]) -> [i16; N] {
    let mut buf = [0i16; 64];
    for n in 0..N {
        buf[10 + n] = synth_sample(ops, a, x[n], &buf[..10 + n]);
    }
    let mut out = [0i16; N];
    out.copy_from_slice(&buf[10..10 + N]);
    out
}
