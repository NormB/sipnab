// SPDX-License-Identifier: MIT OR Apache-2.0

//! Sorting with a type-erased comparator, to stop one algorithm being emitted
//! once per closure.
//!
//! `slice::sort_by` is generic over the comparator, so the compiler emits a
//! fresh copy of the whole stable sort for every CLOSURE type it is called
//! with — not for every element type. Twelve call sites sorting one type
//! twelve different ways produce twelve copies of the same algorithm.
//!
//! Measured on a release build of this crate (aarch64, the musl feature set),
//! `core::slice::sort::stable::quicksort` alone appeared **66 times for
//! 153,248 bytes**, and 39 of those instantiations named a sipnab type. With
//! the helpers it calls -- `drift::sort`, `median3_rec`, `sort4_stable` and
//! the unstable variant -- the sort machinery totalled roughly 322 KB. The
//! release gate that measures the published binary is what turned this from
//! trivia into a number worth acting on.
//!
//! Passing the comparator as `&mut dyn FnMut` collapses that to ONE copy per
//! element type, whatever the call site. The ordering is unchanged: the same
//! stable sort runs with the same comparator, so a caller cannot tell the
//! difference except by measuring the binary.
//!
//! # When NOT to use this
//!
//! The comparator becomes an indirect call, one per comparison. That is
//! irrelevant where a report or a response is being assembled, and it is not
//! irrelevant on the packet path. Sorting inside `pipeline` or
//! `capture::reassembly` runs per packet on a capture that may hold millions
//! of them; those call sites keep the monomorphized `sort_by` on purpose, and
//! pay for it in bytes.

use std::cmp::Ordering;

/// Stable-sort `slice` with a type-erased comparator.
///
/// Same ordering as [`slice::sort_by`] — the same algorithm, the same
/// comparator, one shared copy.
///
/// # Arguments
///
/// * `slice` — what to sort, in place.
/// * `cmp` — the comparison, as a trait object so every call site over one
///   element type shares a single instantiation.
pub fn sort_by_dyn<T>(slice: &mut [T], cmp: &mut dyn FnMut(&T, &T) -> Ordering) {
    slice.sort_by(|a, b| cmp(a, b));
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The point of the helper is that it sorts identically. If it did not,
    /// every report and every response it touches would reorder.
    #[test]
    fn it_orders_exactly_as_sort_by_does() {
        let input = vec![3_i32, 1, 4, 1, 5, 9, 2, 6, 5, 3, 5];

        let mut expected = input.clone();
        expected.sort_by(|a, b| b.cmp(a));

        let mut got = input.clone();
        sort_by_dyn(&mut got, &mut |a, b| b.cmp(a));

        assert_eq!(got, expected, "a type-erased comparator must not reorder");
    }

    /// Stability is part of the contract callers already rely on: `sort_by`
    /// keeps equal elements in their original order, and so must this.
    ///
    /// `unnecessary_sort_by` is allowed on purpose. Clippy is right that
    /// `sort_by_key` expresses this comparison better, and taking its advice
    /// would delete the thing under test: the point is parity with `sort_by`
    /// itself, because that is the call these helpers replace at seventeen
    /// sites. Rewriting the baseline to a different sort would leave the
    /// assertion comparing `sort_by_dyn` against something it is not standing
    /// in for.
    #[test]
    #[allow(clippy::unnecessary_sort_by)]
    fn it_keeps_equal_elements_in_their_original_order() {
        // Second field distinguishes otherwise-equal keys.
        let input = vec![(1, 'a'), (0, 'b'), (1, 'c'), (0, 'd'), (1, 'e')];

        let mut expected = input.clone();
        expected.sort_by(|a, b| a.0.cmp(&b.0));

        let mut got = input.clone();
        sort_by_dyn(&mut got, &mut |a, b| a.0.cmp(&b.0));

        assert_eq!(got, expected);
        assert_eq!(
            got,
            vec![(0, 'b'), (0, 'd'), (1, 'a'), (1, 'c'), (1, 'e')],
            "equal keys must stay in the order they arrived"
        );
    }
}
