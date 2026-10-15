// SPDX-License-Identifier: MIT OR Apache-2.0

//! The ITU-T basic operators (G.729 clause 5.2, Table 11), with the
//! saturation and rounding semantics of the ITU-T Software Tool Library
//! (G.191, STL manual chapter "BASOP: ITU-T Basic Operators"), plus the
//! "extended basic operators" G.729 Table 15 names (oper_32b): a 32-bit value
//! split into a 16-bit high part and a 15-bit low part, and the products of
//! that pair; and the base-2 logarithm, base-2 power and inverse square root
//! lookups of clauses 3.9.1 and 4.2.4.
//!
//! The split-product semantics and the lookup interpolations are not given by
//! the Recommendation text. They were established by matching the oracle's
//! per-subframe traces bit for bit (see the stage tests); each is listed as an
//! open question for confirmation.
//!
//! Every operator that saturates sets [`Ctx::overflow`] when it does, as the
//! reference's overflow indicator does; G.729 clause 4.1.6 synthesis uses that
//! indicator to detect a saturated subframe (see `synth`). Operators that
//! cannot saturate are free functions. No operator wraps or panics, except
//! the shift count of [`Ctx::base2_power`] for an `integer` below -32737 (see
//! its `# Panics` section).

/// Carries the overflow indicator of the basic operators.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Ctx {
    /// Set by any operator whose exact result did not fit and was saturated.
    pub overflow: bool,
}

const MAX_16: i32 = i16::MAX as i32;
const MIN_16: i32 = i16::MIN as i32;

impl Ctx {
    /// Saturate a 32-bit value to 16 bits (`sature`).
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
    /// let mut ops = Ctx::default();
    /// assert_eq!(ops.sat16(100), 100);
    /// assert!(!ops.overflow);
    /// assert_eq!(ops.sat16(40_000), i16::MAX);
    /// assert!(ops.overflow);
    /// ```
    pub fn sat16(&mut self, x: i32) -> i16 {
        if x > MAX_16 {
            self.overflow = true;
            i16::MAX
        } else if x < MIN_16 {
            self.overflow = true;
            i16::MIN
        } else {
            x as i16
        }
    }

    /// Saturate a 64-bit value to 32 bits.
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
    /// let mut ops = Ctx::default();
    /// assert_eq!(ops.sat32(-100), -100);
    /// assert_eq!(ops.sat32(i64::from(i32::MIN) - 1), i32::MIN);
    /// assert!(ops.overflow);
    /// ```
    pub fn sat32(&mut self, x: i64) -> i32 {
        if x > i64::from(i32::MAX) {
            self.overflow = true;
            i32::MAX
        } else if x < i64::from(i32::MIN) {
            self.overflow = true;
            i32::MIN
        } else {
            x as i32
        }
    }

    /// `add(v1, v2)`: 16-bit addition with saturation.
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
    /// let mut ops = Ctx::default();
    /// assert_eq!(ops.add(100, 200), 300);
    /// assert_eq!(ops.add(i16::MAX, 1), i16::MAX);
    /// assert!(ops.overflow);
    /// ```
    pub fn add(&mut self, a: i16, b: i16) -> i16 {
        self.sat16(i32::from(a) + i32::from(b))
    }

    /// `sub(v1, v2)`: 16-bit subtraction with saturation.
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
    /// let mut ops = Ctx::default();
    /// assert_eq!(ops.sub(100, 300), -200);
    /// assert_eq!(ops.sub(i16::MIN, 1), i16::MIN);
    /// assert!(ops.overflow);
    /// ```
    pub fn sub(&mut self, a: i16, b: i16) -> i16 {
        self.sat16(i32::from(a) - i32::from(b))
    }

    /// `negate(v1)` = `sub(0, v1)`.
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
    /// let mut ops = Ctx::default();
    /// assert_eq!(ops.negate(100), -100);
    /// assert_eq!(ops.negate(i16::MIN), i16::MAX);
    /// ```
    pub fn negate(&mut self, a: i16) -> i16 {
        self.sub(0, a)
    }

    /// `shl(v1, v2)`: arithmetic left shift with saturation; a negative
    /// count shifts right with sign extension.
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
    /// let mut ops = Ctx::default();
    /// assert_eq!(ops.shl(100, 2), 400);
    /// assert_eq!(ops.shl(100, -2), 25);
    /// assert_eq!(ops.shl(20_000, 1), i16::MAX);
    /// assert!(ops.overflow);
    /// ```
    pub fn shl(&mut self, a: i16, n: i16) -> i16 {
        if n < 0 {
            return shr_pos(a, n.unsigned_abs());
        }
        if n >= 16 {
            return if a == 0 {
                0
            } else {
                self.sat16(if a > 0 { MAX_16 + 1 } else { MIN_16 - 1 })
            };
        }
        self.sat16(i32::from(a) << n)
    }

    /// `shr(v1, v2)`: arithmetic right shift; a negative count is `shl`.
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
    /// let mut ops = Ctx::default();
    /// assert_eq!(ops.shr(400, 2), 100);
    /// assert_eq!(ops.shr(-400, 2), -100);
    /// assert_eq!(ops.shr(100, -2), 400);
    /// ```
    pub fn shr(&mut self, a: i16, n: i16) -> i16 {
        if n < 0 {
            return self.shl(a, n.saturating_neg());
        }
        shr_pos(a, n.unsigned_abs())
    }

    /// `shr_r(v1, v2)`: `shr` with rounding (adds the last bit shifted out).
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
    /// let mut ops = Ctx::default();
    /// assert_eq!(ops.shr_r(6, 2), 2);
    /// assert_eq!(ops.shr(6, 2), 1);
    /// ```
    pub fn shr_r(&mut self, a: i16, n: i16) -> i16 {
        if n <= 0 {
            return self.shr(a, n);
        }
        if n > 15 {
            return 0;
        }
        let r = i32::from(a) >> (n - 1);
        // (r + 1) >> 1 never exceeds 16 bits for n >= 1.
        ((r + 1) >> 1) as i16
    }

    /// `mult(v1, v2)`: (v1 * v2) >> 15, saturated (`mult(-32768,-32768)` = 32767).
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
    /// let mut ops = Ctx::default();
    /// // 0.5 * 0.5 = 0.25 in Q15.
    /// assert_eq!(ops.mult(16384, 16384), 8192);
    /// assert_eq!(ops.mult(i16::MIN, i16::MIN), i16::MAX);
    /// ```
    pub fn mult(&mut self, a: i16, b: i16) -> i16 {
        self.sat16((i32::from(a) * i32::from(b)) >> 15)
    }

    /// `mult_r(v1, v2)`: (v1 * v2 + 16384) >> 15, saturated.
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
    /// let mut ops = Ctx::default();
    /// assert_eq!(ops.mult_r(16384, 16384), 8192);
    /// assert_eq!(ops.mult_r(1, 16384), 1);
    /// assert_eq!(ops.mult(1, 16384), 0);
    /// ```
    pub fn mult_r(&mut self, a: i16, b: i16) -> i16 {
        self.sat16((i32::from(a) * i32::from(b) + 16384) >> 15)
    }

    /// `L_mult(v1, v2)`: 2 * v1 * v2, saturated (only -32768 * -32768 saturates).
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
    /// let mut ops = Ctx::default();
    /// assert_eq!(ops.l_mult(100, 200), 40_000);
    /// assert_eq!(ops.l_mult(i16::MIN, i16::MIN), i32::MAX);
    /// assert!(ops.overflow);
    /// ```
    pub fn l_mult(&mut self, a: i16, b: i16) -> i32 {
        self.sat32(2 * i64::from(a) * i64::from(b))
    }

    /// `L_add(L_v1, L_v2)`: 32-bit addition with saturation.
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
    /// let mut ops = Ctx::default();
    /// assert_eq!(ops.l_add(100_000, 200_000), 300_000);
    /// assert_eq!(ops.l_add(i32::MAX, 1), i32::MAX);
    /// ```
    pub fn l_add(&mut self, a: i32, b: i32) -> i32 {
        self.sat32(i64::from(a) + i64::from(b))
    }

    /// `L_sub(L_v1, L_v2)`: 32-bit subtraction with saturation.
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
    /// let mut ops = Ctx::default();
    /// assert_eq!(ops.l_sub(100_000, 300_000), -200_000);
    /// assert_eq!(ops.l_sub(i32::MIN, 1), i32::MIN);
    /// ```
    pub fn l_sub(&mut self, a: i32, b: i32) -> i32 {
        self.sat32(i64::from(a) - i64::from(b))
    }

    /// `L_negate(L_v1)`, saturating -2^31 to 2^31 - 1.
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
    /// let mut ops = Ctx::default();
    /// assert_eq!(ops.l_negate(100), -100);
    /// assert_eq!(ops.l_negate(i32::MIN), i32::MAX);
    /// ```
    pub fn l_negate(&mut self, a: i32) -> i32 {
        self.sat32(-i64::from(a))
    }

    /// `L_mac(L_v3, v1, v2)` = `L_add(L_v3, L_mult(v1, v2))`.
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
    /// let mut ops = Ctx::default();
    /// assert_eq!(ops.l_mac(1_000, 100, 200), 41_000);
    /// ```
    pub fn l_mac(&mut self, acc: i32, a: i16, b: i16) -> i32 {
        let p = self.l_mult(a, b);
        self.l_add(acc, p)
    }

    /// `L_msu(L_v3, v1, v2)` = `L_sub(L_v3, L_mult(v1, v2))`.
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
    /// let mut ops = Ctx::default();
    /// assert_eq!(ops.l_msu(41_000, 100, 200), 1_000);
    /// ```
    pub fn l_msu(&mut self, acc: i32, a: i16, b: i16) -> i32 {
        let p = self.l_mult(a, b);
        self.l_sub(acc, p)
    }

    /// `L_shl(L_v1, v2)`: 32-bit arithmetic left shift with saturation; a
    /// negative count shifts right.
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
    /// let mut ops = Ctx::default();
    /// assert_eq!(ops.l_shl(100, 4), 1_600);
    /// assert_eq!(ops.l_shl(1_600, -4), 100);
    /// assert_eq!(ops.l_shl(1 << 30, 1), i32::MAX);
    /// assert!(ops.overflow);
    /// ```
    pub fn l_shl(&mut self, a: i32, n: i16) -> i32 {
        if n < 0 {
            return l_shr_pos(a, n.unsigned_abs());
        }
        if n >= 32 {
            return if a == 0 {
                0
            } else {
                self.sat32(if a > 0 { i64::MAX } else { i64::MIN })
            };
        }
        self.sat32(i64::from(a) << n)
    }

    /// `L_shr(L_v1, v2)`: 32-bit arithmetic right shift; negative is `L_shl`.
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
    /// let mut ops = Ctx::default();
    /// assert_eq!(ops.l_shr(1_600, 4), 100);
    /// assert_eq!(ops.l_shr(-1_600, 4), -100);
    /// ```
    pub fn l_shr(&mut self, a: i32, n: i16) -> i32 {
        if n < 0 {
            return self.l_shl(a, n.saturating_neg());
        }
        l_shr_pos(a, n.unsigned_abs())
    }

    /// `L_shr_r(L_v1, v2)`: `L_shr` with rounding.
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
    /// let mut ops = Ctx::default();
    /// assert_eq!(ops.l_shr_r(6, 2), 2);
    /// assert_eq!(ops.l_shr(6, 2), 1);
    /// ```
    pub fn l_shr_r(&mut self, a: i32, n: i16) -> i32 {
        if n <= 0 {
            return self.l_shr(a, n);
        }
        if n > 31 {
            return 0;
        }
        let r = i64::from(a) >> (n - 1);
        ((r + 1) >> 1) as i32
    }

    /// `round(L_v1)` = `extract_h(L_add(L_v1, 32768))`.
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
    /// let mut ops = Ctx::default();
    /// assert_eq!(ops.round(0x0001_8000), 2);
    /// assert_eq!(ops.round(0x0001_7fff), 1);
    /// ```
    pub fn round(&mut self, a: i32) -> i16 {
        extract_h(self.l_add(a, 0x8000))
    }

    /// `mac_r(L_v3, v1, v2)` = `round(L_mac(L_v3, v1, v2))`.
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
    /// let mut ops = Ctx::default();
    /// // round(0 + 2 * 16384 * 4) = 2.
    /// assert_eq!(ops.mac_r(0, 16384, 4), 2);
    /// ```
    pub fn mac_r(&mut self, acc: i32, a: i16, b: i16) -> i16 {
        let s = self.l_mac(acc, a, b);
        self.round(s)
    }

    /// `msu_r(L_v3, v1, v2)` = `round(L_msu(L_v3, v1, v2))`.
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
    /// let mut ops = Ctx::default();
    /// // round(0x0004_0000 - 2 * 16384 * 4) = 2.
    /// assert_eq!(ops.msu_r(0x0004_0000, 16384, 4), 2);
    /// ```
    pub fn msu_r(&mut self, acc: i32, a: i16, b: i16) -> i16 {
        let s = self.l_msu(acc, a, b);
        self.round(s)
    }

    /// `L_abs(L_v1)`, with `L_abs(-2^31)` = 2^31 - 1.
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
    /// let mut ops = Ctx::default();
    /// assert_eq!(ops.l_abs(-100), 100);
    /// assert_eq!(ops.l_abs(i32::MIN), i32::MAX);
    /// ```
    pub fn l_abs(&mut self, a: i32) -> i32 {
        self.sat32(i64::from(a).abs())
    }
}

impl Ctx {
    /// A 32-bit value as a pair: its upper 16 bits, and the 15 bits below
    /// them; the value equals `upper` * 2^16 + `lower` * 2 plus its last bit.
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
    /// let mut ops = Ctx::default();
    /// let (upper, lower) = ops.split_high_low(0x0003_0010);
    /// assert_eq!((upper, lower), (3, 8));
    /// assert_eq!(ops.join_high_low(upper, lower), 0x0003_0010);
    /// ```
    pub fn split_high_low(&mut self, value: i32) -> (i16, i16) {
        let upper = extract_h(value);
        let halved = value >> 1;
        let remainder = self.l_msu(halved, upper, 16384);
        (upper, extract_l(remainder))
    }

    /// The 32-bit value `upper` * 2^16 + `lower` * 2.
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
    /// let mut ops = Ctx::default();
    /// assert_eq!(ops.join_high_low(3, 8), 0x0003_0010);
    /// ```
    pub fn join_high_low(&mut self, upper: i16, lower: i16) -> i32 {
        self.l_mac(l_deposit_h(upper), lower, 1)
    }

    /// A value given as (`upper`, `lower`) times the 16-bit `factor`:
    /// `L_mult(upper, factor)` plus twice `mult(lower, factor)`.
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
    /// let mut ops = Ctx::default();
    /// // (3 * 2^16 + 8 * 2) * 0.5 (16384 in Q15).
    /// assert_eq!(ops.multiply_split_by_16(3, 8, 16384), 0x0001_8008);
    /// ```
    pub fn multiply_split_by_16(&mut self, upper: i16, lower: i16, factor: i16) -> i32 {
        let coarse = self.l_mult(upper, factor);
        let fine = self.mult(lower, factor);
        self.l_mac(coarse, fine, 1)
    }

    /// A 32-bit value times a 16-bit factor, through its (upper, lower) pair.
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
    /// let mut ops = Ctx::default();
    /// assert_eq!(ops.multiply_32_by_16(0x0003_0010, 16384), 0x0001_8008);
    /// ```
    pub fn multiply_32_by_16(&mut self, value: i32, factor: i16) -> i32 {
        let (upper, lower) = self.split_high_low(value);
        self.multiply_split_by_16(upper, lower, factor)
    }

    /// Linear interpolation in a Q15/Q14 lookup: entry `index` moved toward
    /// entry `index + 1` by `weight` (Q15), in the upper half of the result.
    fn interpolate_q15(&mut self, table: &[i16], index: usize, weight: i16) -> i32 {
        let step = self.sub(table[index], table[index + 1]);
        self.l_msu(l_deposit_h(table[index]), step, weight)
    }

    /// Base-2 logarithm of a positive 32-bit value: (integer part, fraction
    /// Q15), interpolated in `table` (log2(1 + i/32), Q15). A value that is
    /// not positive gives (0, 0).
    ///
    /// # Panics
    ///
    /// Does not panic.
    pub fn base2_log(&mut self, value: i32, table: &[i16; 33]) -> (i16, i16) {
        if value <= 0 {
            return (0, 0);
        }
        let left = norm_l(value);
        let normalized = self.l_shl(value, left);
        let segment = ((normalized >> 25) - 32) as usize;
        let weight = ((normalized >> 10) & 0x7fff) as i16;
        let fraction = extract_h(self.interpolate_q15(table, segment, weight));
        (30 - left, fraction)
    }

    /// 2^(`integer` + `fraction`) in 32 bits, interpolated in the Q14 table
    /// 2^(i/32), shifted right (rounded) by 30 - `integer`.
    ///
    /// # Panics
    ///
    /// In a build with overflow checks (such as the default `dev` profile), panics when `integer` is below -32737, where 30 - `integer` overflows `i16`. A build without overflow checks does not panic.
    ///
    /// # Examples
    ///
    /// ```
    /// use g729::basic_op::Ctx;
    ///
    /// let mut ops = Ctx::default();
    /// // 2^(0 + 0) = 1, and 2^(4 + 0) = 16.
    /// assert_eq!(ops.base2_power(0, 0), 1);
    /// assert_eq!(ops.base2_power(4, 0), 16);
    /// ```
    pub fn base2_power(&mut self, integer: i16, fraction: i16) -> i32 {
        let segment = (fraction >> 10) as usize & 31;
        let weight = (fraction & 0x3ff) << 5;
        let mantissa = self.interpolate_q15(&crate::tables::formula::POW2, segment, weight);
        self.l_shr_r(mantissa, 30 - integer)
    }

    /// 2^30/sqrt(`value`) of a positive 32-bit value, interpolated in the Q15
    /// table 1/sqrt(1 + i/16). A value that is not positive gives 2^30 - 1.
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
    /// let mut ops = Ctx::default();
    /// assert_eq!(ops.inverse_square_root(0), 0x3fff_ffff);
    /// // 2^30 / sqrt(2^30) = 2^15, to within the lookup's interpolation.
    /// let root = ops.inverse_square_root(1 << 30);
    /// assert!((root - (1 << 15)).abs() <= 1);
    /// ```
    pub fn inverse_square_root(&mut self, value: i32) -> i32 {
        if value <= 0 {
            return 0x3fff_ffff;
        }
        let left = norm_l(value);
        let magnitude = 30 - left;
        // An even magnitude takes one more halving, so that the root of the
        // power of two is exact.
        let normalized = if magnitude & 1 == 0 {
            self.l_shl(value, left) >> 1
        } else {
            self.l_shl(value, left)
        };
        let segment = ((normalized >> 25) - 16) as usize;
        let weight = ((normalized >> 10) & 0x7fff) as i16;
        let mantissa = self.interpolate_q15(&crate::tables::formula::INVERSE_SQRT, segment, weight);
        self.l_shr(mantissa, (magnitude >> 1) + 1)
    }
}

fn shr_pos(a: i16, n: u16) -> i16 {
    if n >= 15 {
        if a < 0 { -1 } else { 0 }
    } else {
        a >> n
    }
}

fn l_shr_pos(a: i32, n: u16) -> i32 {
    if n >= 31 {
        if a < 0 { -1 } else { 0 }
    } else {
        a >> n
    }
}

/// `abs_s(v1)`, with `abs_s(-32768)` = 32767.
///
/// # Panics
///
/// Does not panic.
///
/// # Examples
///
/// ```
/// use g729::basic_op::abs_s;
///
/// assert_eq!(abs_s(-100), 100);
/// assert_eq!(abs_s(i16::MIN), i16::MAX);
/// ```
pub fn abs_s(a: i16) -> i16 {
    if a == i16::MIN { i16::MAX } else { a.abs() }
}

/// `extract_h(L_v1)`: the 16 most significant bits.
///
/// # Panics
///
/// Does not panic.
///
/// # Examples
///
/// ```
/// use g729::basic_op::extract_h;
///
/// assert_eq!(extract_h(0x0003_0010), 3);
/// assert_eq!(extract_h(-1), -1);
/// ```
pub fn extract_h(a: i32) -> i16 {
    (a >> 16) as i16
}

/// `extract_l(L_v1)`: the 16 least significant bits.
///
/// # Panics
///
/// Does not panic.
///
/// # Examples
///
/// ```
/// use g729::basic_op::extract_l;
///
/// assert_eq!(extract_l(0x0003_0010), 0x10);
/// ```
pub fn extract_l(a: i32) -> i16 {
    a as i16
}

/// `L_deposit_h(v1)`: v1 in the 16 most significant bits.
///
/// # Panics
///
/// Does not panic.
///
/// # Examples
///
/// ```
/// use g729::basic_op::l_deposit_h;
///
/// assert_eq!(l_deposit_h(3), 0x0003_0000);
/// assert_eq!(l_deposit_h(-1), -0x0001_0000);
/// ```
pub fn l_deposit_h(a: i16) -> i32 {
    i32::from(a) << 16
}

/// `L_deposit_l(v1)`: v1 sign-extended to 32 bits.
///
/// # Panics
///
/// Does not panic.
///
/// # Examples
///
/// ```
/// use g729::basic_op::l_deposit_l;
///
/// assert_eq!(l_deposit_l(-3), -3);
/// ```
pub fn l_deposit_l(a: i16) -> i32 {
    i32::from(a)
}

/// `norm_s(v1)`: left shifts that bring v1 into [16384, 32767] or
/// [-32768, -16384]; 0 for 0.
///
/// A negative power of two is shifted to -32768 (`norm_s(-1)` = 15,
/// `norm_s(-16384)` = 1), as the oracle's reference rows show.
///
/// # Panics
///
/// Does not panic.
///
/// # Examples
///
/// ```
/// use g729::basic_op::norm_s;
///
/// assert_eq!(norm_s(0), 0);
/// assert_eq!(norm_s(1), 14);
/// assert_eq!(norm_s(16384), 0);
/// assert_eq!(norm_s(-1), 15);
/// ```
pub fn norm_s(a: i16) -> i16 {
    let mut v = i32::from(a);
    if v == 0 {
        return 0;
    }
    let mut n = 0;
    if v > 0 {
        while v < 0x4000 {
            v <<= 1;
            n += 1;
        }
    } else {
        while v >= -0x4000 {
            v <<= 1;
            n += 1;
        }
    }
    n
}

/// `norm_l(L_v1)`: left shifts that bring L_v1 into [2^30, 2^31 - 1] or
/// [-2^31, -2^30]; 0 for 0.
///
/// Negative inputs follow the same rule as [`norm_s`].
///
/// # Panics
///
/// Does not panic.
///
/// # Examples
///
/// ```
/// use g729::basic_op::norm_l;
///
/// assert_eq!(norm_l(0), 0);
/// assert_eq!(norm_l(1), 30);
/// assert_eq!(norm_l(-1), 31);
/// ```
pub fn norm_l(a: i32) -> i16 {
    let mut v = i64::from(a);
    if v == 0 {
        return 0;
    }
    let mut n = 0;
    if v > 0 {
        while v < 0x4000_0000 {
            v <<= 1;
            n += 1;
        }
    } else {
        while v >= -0x4000_0000 {
            v <<= 1;
            n += 1;
        }
    }
    n
}

/// `div_s(v1, v2)`: fractional division v1 / v2 for 0 <= v1 <= v2, v2 > 0,
/// truncated to 15 fractional bits; 32767 when v1 == v2. Out-of-domain
/// inputs (which the decoder never produces) return 0 instead of aborting.
///
/// # Panics
///
/// Does not panic.
///
/// # Examples
///
/// ```
/// use g729::basic_op::div_s;
///
/// // 1 / 4 = 0.25 in Q15.
/// assert_eq!(div_s(1, 4), 8192);
/// assert_eq!(div_s(7, 7), i16::MAX);
/// assert_eq!(div_s(5, 4), 0);
/// ```
pub fn div_s(num: i16, den: i16) -> i16 {
    if num <= 0 || den <= 0 || num > den {
        return 0;
    }
    if num == den {
        return i16::MAX;
    }
    let mut n = i32::from(num);
    let d = i32::from(den);
    let mut q: i32 = 0;
    for _ in 0..15 {
        q <<= 1;
        n <<= 1;
        if n >= d {
            n -= d;
            q += 1;
        }
    }
    q as i16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_and_sub_saturate_and_flag() {
        let mut c = Ctx::default();
        assert_eq!(c.add(1, 2), 3);
        assert!(!c.overflow);
        assert_eq!(c.add(32767, 1), 32767);
        assert!(c.overflow);
        let mut c = Ctx::default();
        assert_eq!(c.sub(-32768, 1), -32768);
        assert!(c.overflow);
        assert_eq!(Ctx::default().negate(-32768), 32767);
    }

    #[test]
    fn shifts_saturate_and_negative_counts_reverse() {
        let mut c = Ctx::default();
        assert_eq!(c.shl(0x4000, 1), 32767);
        assert!(c.overflow);
        assert_eq!(Ctx::default().shl(-3, -1), -2);
        assert_eq!(Ctx::default().shr(-3, 1), -2);
        assert_eq!(Ctx::default().shr(1, -2), 4);
        assert_eq!(Ctx::default().shr(-1, 40), -1);
        assert_eq!(Ctx::default().l_shl(0x4000_0000, 1), i32::MAX);
        assert_eq!(Ctx::default().l_shl(-0x4000_0001, 1), i32::MIN);
        assert_eq!(Ctx::default().l_shr(-5, 1), -3);
    }

    #[test]
    fn rounding_shifts_add_the_last_bit_out() {
        assert_eq!(Ctx::default().shr_r(5, 1), 3);
        assert_eq!(Ctx::default().shr_r(-5, 1), -2);
        assert_eq!(Ctx::default().shr_r(4, 1), 2);
        assert_eq!(Ctx::default().l_shr_r(5, 1), 3);
        assert_eq!(Ctx::default().l_shr_r(-6, 2), -1);
        assert_eq!(Ctx::default().l_shr_r(i32::MAX, 1), 0x4000_0000);
    }

    #[test]
    fn multiplications_match_the_stl_definitions() {
        let mut c = Ctx::default();
        assert_eq!(c.mult(-32768, -32768), 32767);
        assert!(c.overflow);
        assert_eq!(Ctx::default().mult(16384, 16384), 8192);
        assert_eq!(Ctx::default().mult(-1, 1), -1);
        assert_eq!(Ctx::default().mult_r(-1, 1), 0);
        assert_eq!(Ctx::default().mult_r(3, 16384), 2);
        let mut c = Ctx::default();
        assert_eq!(c.l_mult(-32768, -32768), i32::MAX);
        assert!(c.overflow);
        assert_eq!(Ctx::default().l_mult(3, -4), -24);
        assert_eq!(Ctx::default().l_mac(10, 3, 4), 34);
        assert_eq!(Ctx::default().l_msu(10, 3, 4), -14);
    }

    #[test]
    fn round_and_mac_r_saturate() {
        let mut c = Ctx::default();
        assert_eq!(c.round(0x7FFF_8000), 32767);
        assert!(c.overflow);
        assert_eq!(Ctx::default().round(0x0001_7FFF), 1);
        assert_eq!(Ctx::default().round(0x0001_8000), 2);
        assert_eq!(Ctx::default().round(-0x8000), 0);
        assert_eq!(Ctx::default().mac_r(0, 16384, 16384), 8192);
        assert_eq!(Ctx::default().msu_r(0, 16384, 16384), -8192);
    }

    #[test]
    fn conversions_and_norms() {
        assert_eq!(extract_h(0x1234_5678), 0x1234);
        assert_eq!(extract_l(0x1234_5678), 0x5678);
        assert_eq!(l_deposit_h(-2), -0x2_0000);
        assert_eq!(l_deposit_l(-2), -2);
        assert_eq!(abs_s(-32768), 32767);
        assert_eq!(Ctx::default().l_abs(i32::MIN), i32::MAX);
        assert_eq!(norm_s(0), 0);
        assert_eq!(norm_s(1), 14);
        assert_eq!(norm_s(16384), 0);
        assert_eq!(norm_s(-16384), 1);
        assert_eq!(norm_s(-16385), 0);
        assert_eq!(norm_s(-1), 15);
        assert_eq!(norm_s(-3), 13);
        assert_eq!(norm_s(-32768), 0);
        assert_eq!(norm_l(1), 30);
        assert_eq!(norm_l(-1), 31);
        assert_eq!(norm_l(-0x4000_0000), 1);
        assert_eq!(norm_l(-0x4000_0001), 0);
        assert_eq!(norm_l(i32::MIN), 0);
        assert_eq!(norm_l(0x4000_0000), 0);
    }

    #[test]
    fn split_products_and_lookups() {
        let mut c = Ctx::default();
        let (hi, lo) = c.split_high_low(0x1234_5678);
        assert_eq!((hi, lo), (0x1234, 0x5678 >> 1));
        assert_eq!(c.join_high_low(hi, lo), 0x1234_5678 & !1);
        // 0.5 * 1.0 in the split format.
        assert_eq!(c.multiply_32_by_16(0x4000_0000, 0x4000), 0x2000_0000);
        // 2^(14 + 0) = 16384 in Q0 after the shift by 30 - 14.
        assert_eq!(c.base2_power(14, 0), 16384);
        assert_eq!(c.inverse_square_root(1 << 30), 32767);
        assert_eq!(c.inverse_square_root(1 << 28), 65534);
        let mut log = [0i16; 33];
        for (i, v) in log.iter_mut().enumerate() {
            *v = (i as i16) * 1000;
        }
        // A synthetic linear table: log2(2^20) = (20, 0).
        assert_eq!(c.base2_log(1 << 20, &log), (20, 0));
        assert_eq!(c.base2_log(0, &log), (0, 0));
        assert!(!c.overflow);
    }

    #[test]
    fn div_s_is_truncated_fractional_division() {
        assert_eq!(div_s(1, 2), 16384);
        assert_eq!(div_s(1, 3), 10922);
        assert_eq!(div_s(5, 5), 32767);
        assert_eq!(div_s(0, 5), 0);
        assert_eq!(div_s(16384, 32767), 16384);
    }
}
