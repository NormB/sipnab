// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! Adaptive codebook: pitch-delay decoding (G.729 clauses 4.1.2 and 4.1.3,
//! with the parity check of clause 3.7.2), the concealment delay of clause
//! 4.4.4, and the fractional-delay adaptive-codebook vector of equation (40)
//! (clause 3.7.1).

use crate::basic_op::Ctx;
use crate::tables::{Scalar, Tables, text};

/// Samples of past excitation the decoder keeps: the largest delay (143)
/// plus the interpolation span (10) plus one.
pub const PAST: usize = 154;

/// Clause 3.7.2: the parity bit P0 must equal 1 XOR the XOR of the six MSBs
/// of the 8-bit index P1.
///
/// # Panics
///
/// Does not panic.
///
/// # Examples
///
/// ```
/// // P1 = 0: the XOR of its six MSBs is 0, so P0 must be 1.
/// assert!(g729::adaptive::parity_ok(0, 1));
/// assert!(!g729::adaptive::parity_ok(0, 0));
/// ```
pub fn parity_ok(p1: u16, p0: u16) -> bool {
    let mut x = 1u16;
    for b in 2..8 {
        x ^= (p1 >> b) & 1;
    }
    x == (p0 & 1)
}

/// Clause 4.1.3: T1 from P1, as (integer part, fraction in thirds).
///
/// Only the 8 low bits of `p1` are read.
///
/// # Panics
///
/// Does not panic.
///
/// # Examples
///
/// ```
/// use g729::adaptive::decode_t1;
///
/// // Below 197: a delay in thirds, from 19 + 1/3 upward.
/// assert_eq!(decode_t1(0), (19, 1));
/// // From 197: an integer delay, 85 to 143.
/// assert_eq!(decode_t1(197), (85, 0));
/// assert_eq!(decode_t1(255), (143, 0));
/// ```
pub fn decode_t1(p1: u16) -> (i16, i16) {
    let p1 = (p1 & 0xff) as i16;
    if p1 < 197 {
        let int = (p1 + 2) / 3 + 19;
        (int, p1 - 3 * int + 58)
    } else {
        (p1 - 112, 0)
    }
}

/// Clause 4.1.3: T2 from P2 and the integer part of T1.
///
/// Only the 5 low bits of `p2` are read. Any `t1` is accepted: the search
/// range is held inside the valid delays.
///
/// # Panics
///
/// Does not panic.
///
/// # Examples
///
/// ```
/// use g729::adaptive::decode_t2;
///
/// // With T1 = 60 the range starts at 55; P2 = 5 is 56 + 0/3.
/// assert_eq!(decode_t2(5, 60), (56, 0));
/// ```
pub fn decode_t2(p2: u16, t1: i16) -> (i16, i16) {
    let p2 = (p2 & 31) as i16;
    // t1 is at most the maximum delay for a valid stream; saturate anyway so
    // that no input can overflow.
    let mut tmin = t1.saturating_sub(5).min(text::PITCH_DELAY_MAX);
    if tmin < text::PITCH_DELAY_MIN {
        tmin = text::PITCH_DELAY_MIN;
    }
    let tmax = tmin + 9;
    if tmax > text::PITCH_DELAY_MAX {
        tmin = text::PITCH_DELAY_MAX - 9;
    }
    let k = (p2 + 2) / 3 - 1;
    (k + tmin, p2 - 2 - 3 * k)
}

/// The integer delay carried from frame to frame for concealment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PitchState {
    old: i16,
}

impl PitchState {
    /// Initial state.
    ///
    /// # Panics
    ///
    /// Does not panic.
    pub fn new(tables: &Tables) -> Self {
        PitchState {
            old: tables.scalar(Scalar::InitialPreviousPitchDelay),
        }
    }

    /// Subframe 1 of a received frame. With a parity error (clause 4.1.2)
    /// T1 is the previous integer delay.
    ///
    /// # Panics
    ///
    /// Does not panic.
    pub fn first(&mut self, p1: u16, parity_ok: bool) -> (i16, i16) {
        let d = if parity_ok {
            decode_t1(p1)
        } else {
            (self.old, 0)
        };
        self.old = d.0;
        d
    }

    /// Subframe 2 of a received frame.
    ///
    /// # Panics
    ///
    /// Does not panic.
    pub fn second(&mut self, p2: u16, t1: i16) -> (i16, i16) {
        let d = decode_t2(p2, t1);
        self.old = d.0;
        d
    }

    /// A subframe of an erased frame (clause 4.4.4): the previous integer
    /// delay, which then grows by one, up to the maximum delay.
    ///
    /// # Panics
    ///
    /// Does not panic.
    pub fn erased(&mut self) -> (i16, i16) {
        let d = (self.old, 0);
        // The next delay is one more, bounded by the maximum delay: a carried
        // delay above it (144, from a fraction of -1 at the top of the range)
        // drops back to the maximum.
        self.old = self.old.saturating_add(1).min(text::PITCH_DELAY_MAX);
        d
    }
}

/// Equation (40): v(n) for n = 0..39 at delay `t0` + `frac`/3, written into
/// `exc[pos..pos + 40]`. Samples of `exc` before `pos` are the past
/// excitation; for delays below 40 the vector's own first samples feed its
/// later ones, as in the adaptive-codebook approach.
///
/// # Panics
///
/// Panics if `exc.len()` is less than `pos + 40`, or if `pos` is less than
/// k + 9, where k is `t0` (plus 1 when `frac` is positive) limited to
/// 10..=144. A `pos` of at least [`PAST`] never panics on the second
/// condition.
pub fn adaptive_vector(
    ops: &mut Ctx,
    tables: &Tables,
    exc: &mut [i16],
    pos: usize,
    t0: i16,
    frac: i16,
) {
    vector_with(ops, &tables.b30, exc, pos, t0, frac);
}

/// Equation (40) with the interpolation filter b30 given explicitly.
pub(crate) fn vector_with(
    ops: &mut Ctx,
    b30: &[i16; 31],
    exc: &mut [i16],
    pos: usize,
    t0: i16,
    frac: i16,
) {
    // T = t0 + frac/3 = k - phase/3.
    let (k, phase) = match frac {
        0 => (t0, 0usize),
        f if f < 0 => (t0, 1),
        _ => (t0.saturating_add(1), 2),
    };
    // Valid streams give 20..=144. The lower bound 10 keeps the look-ahead
    // x + 1 + i (i <= 9) inside the current subframe for any input.
    let k = k.clamp(10, PAST as i16 - 10) as usize;
    let b = b30;
    for n in 0..40 {
        let x = pos + n - k;
        let mut acc = 0i32;
        for i in 0..10 {
            acc = ops.l_mac(acc, exc[x - i], b[phase + 3 * i]);
            acc = ops.l_mac(acc, exc[x + 1 + i], b[3 - phase + 3 * i]);
        }
        exc[pos + n] = ops.round(acc);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn any_delay_stays_inside_the_buffer() {
        // The fuzz target found an initial delay below 10 (from arbitrary
        // table values) reading past the excitation buffer; valid streams
        // never decode a delay below 19.
        let b30 = [1000i16; 31];
        for t0 in [i16::MIN, -5, 0, 1, 5, 9, 10, 19, 143, 200, i16::MAX] {
            for frac in [-1, 0, 1] {
                for pos in [PAST, PAST + 40] {
                    let mut exc = [7i16; PAST + 80];
                    vector_with(&mut Ctx::default(), &b30, &mut exc, pos, t0, frac);
                }
            }
        }
    }
}
