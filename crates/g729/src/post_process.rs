// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! Post-processing: the 100 Hz high-pass filter of G.729 equation (91) and
//! the upscaling by 2 (clause 4.2.5). The recursive part keeps the past
//! outputs in 32 bits and multiplies them through the high/low split.

use crate::basic_op::Ctx;
use crate::tables::formula::{HIGHPASS_DENOMINATOR, HIGHPASS_NUMERATOR};

/// The filter's memory.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HighPass {
    /// sf'(n-1), sf'(n-2): the last two inputs.
    past_inputs: [i16; 2],
    /// The last two outputs before upscaling, in 32 bits, newest first.
    past_outputs: [i32; 2],
}

impl HighPass {
    /// Zero state.
    ///
    /// # Panics
    ///
    /// Does not panic.
    pub fn new() -> Self {
        Self::default()
    }

    /// One sample of equation (91), upscaled by 2. The feedback terms are
    /// accumulated first, then the feedforward terms, newest first: the
    /// additions saturate, so this order is kept.
    fn step(&mut self, ops: &mut Ctx, input: i16) -> i16 {
        let [newest_out, older_out] = self.past_outputs;
        let feedback = [
            (newest_out, HIGHPASS_DENOMINATOR[1]),
            (older_out, HIGHPASS_DENOMINATOR[2]),
        ];
        let [newest_term, older_term] =
            feedback.map(|(past, weight)| ops.multiply_32_by_16(past, weight));
        let recursive = ops.l_add(newest_term, older_term);
        let [newest_in, older_in] = self.past_inputs;
        let feedforward = [
            (input, HIGHPASS_NUMERATOR[0]),
            (newest_in, HIGHPASS_NUMERATOR[1]),
            (older_in, HIGHPASS_NUMERATOR[2]),
        ];
        let total = feedforward
            .iter()
            .fold(recursive, |sum, &(sample, weight)| {
                ops.l_mac(sum, sample, weight)
            });
        let output = ops.l_shl(total, 2);
        self.past_inputs = [input, newest_in];
        self.past_outputs = [output, newest_out];
        let upscaled = ops.l_shl(output, 1);
        ops.round(upscaled)
    }

    /// Filter and upscale one subframe (clause 4.2.5).
    ///
    /// # Panics
    ///
    /// Does not panic.
    ///
    /// # Examples
    ///
    /// ```
    /// use g729::basic_op::Ctx;
    /// use g729::post_process::HighPass;
    ///
    /// let mut filter = HighPass::new();
    /// let mut ops = Ctx::default();
    /// // Silence in, silence out.
    /// assert_eq!(filter.process(&mut ops, &[0; 40]), [0; 40]);
    /// assert!(!ops.overflow);
    /// ```
    pub fn process(&mut self, ops: &mut Ctx, input: &[i16; 40]) -> [i16; 40] {
        input.map(|sample| self.step(ops, sample))
    }
}
