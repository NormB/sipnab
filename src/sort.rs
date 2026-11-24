// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

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
//! the unstable variant -- the sort machinery totaled roughly 322 KB. The
//! release gate that measures the published binary is what turned this from
//! trivia into a number worth acting on.
//!
//! Passing the comparator as `&mut dyn FnMut` collapsed that to one copy per
//! element type. It still left one copy per ELEMENT type: measured 2026-11-21
//! on the release profile and the musl feature set (built for
//! x86_64-unknown-linux-gnu), the 31 call sites of this helper held 93 sort
//! symbols and 144,312 bytes, about 6 KB per element type.
//!
//! So the helper now sorts INDICES. `stable_order` is not generic: it runs
//! the standard stable sort over `0..len`, comparing the elements the indices
//! name, and the binary holds exactly one copy of it. `apply_order` then
//! moves each element once to its place, a small loop per element type. The
//! ordering is unchanged: a stable sort's result is fixed by the comparator
//! alone, so sorting indices with it gives the same permutation as sorting
//! the elements. A caller cannot tell the difference except by measuring the
//! binary; a comparator that panics now leaves the slice as it was.
//!
//! # When NOT to use this
//!
//! The comparator becomes an indirect call, one per comparison, and the sort
//! allocates one `usize` per element. That is irrelevant where a report or a
//! response is being assembled, and it is not irrelevant on the packet path.
//! Sorting inside `pipeline` or `capture::reassembly` runs per packet on a
//! capture that may hold millions of them; those call sites keep the
//! monomorphized `sort_by` on purpose, and pay for it in bytes.

use std::cmp::Ordering;

/// Stable-sort `slice` with a type-erased comparator.
///
/// Same ordering as [`slice::sort_by`] with the same comparator: equal
/// elements keep their order. One shared copy of the sort serves every
/// element type.
///
/// # Arguments
///
/// * `slice` — what to sort, in place.
/// * `cmp` — the comparison, as a trait object so every call site shares the
///   single instantiation in `stable_order`.
pub fn sort_by_dyn<T>(slice: &mut [T], cmp: &mut dyn FnMut(&T, &T) -> Ordering) {
    if slice.len() < 2 {
        return;
    }
    let order = {
        let view: &[T] = slice;
        stable_order(view.len(), &mut |a, b| cmp(&view[a], &view[b]))
    };
    apply_order(slice, order);
}

/// The stable sorted order of `0..len` under `cmp`.
///
/// Deliberately not generic, so the binary carries one copy of the sort.
///
/// # Returns
///
/// `order`, where `order[i]` is the index of the element that belongs at
/// position `i`.
fn stable_order(len: usize, cmp: &mut dyn FnMut(usize, usize) -> Ordering) -> Vec<usize> {
    let mut order: Vec<usize> = (0..len).collect();
    order.sort_by(|&a, &b| cmp(a, b));
    order
}

/// Rearrange `slice` so position `i` holds the element that was at
/// `order[i]`.
///
/// Walks each cycle of the permutation once, swapping, so every element moves
/// at most once per cycle step and nothing is cloned. `order` must be a
/// permutation of `0..slice.len()`, which [`stable_order`] guarantees.
fn apply_order<T>(slice: &mut [T], mut order: Vec<usize>) {
    for start in 0..slice.len() {
        let mut current = start;
        while order[current] != start {
            let next = order[current];
            slice.swap(current, next);
            order[current] = current;
            current = next;
        }
        order[current] = current;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::strategy::Strategy as _;

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

    /// `apply_order` puts at position `i` the element that was at `order[i]`,
    /// for every cycle shape: identity, one swap, one long cycle, and several
    /// cycles at once.
    #[test]
    fn apply_order_moves_each_element_to_its_place() {
        let cases: [(&[usize], &[char]); 5] = [
            (&[0, 1, 2, 3], &['a', 'b', 'c', 'd']),
            (&[1, 0, 2, 3], &['b', 'a', 'c', 'd']),
            (&[3, 0, 1, 2], &['d', 'a', 'b', 'c']),
            (&[1, 2, 3, 0], &['b', 'c', 'd', 'a']),
            (&[1, 0, 3, 2], &['b', 'a', 'd', 'c']),
        ];
        for (order, want) in cases {
            let mut got = vec!['a', 'b', 'c', 'd'];
            apply_order(&mut got, order.to_vec());
            assert_eq!(got, want, "order {order:?} placed the elements wrongly");
        }
    }

    /// An empty slice and a one-element slice come back as they were, and the
    /// comparator is never called for them.
    #[test]
    fn short_slices_are_left_alone_without_comparing() {
        let mut calls = 0usize;
        let mut empty: Vec<u8> = Vec::new();
        sort_by_dyn(&mut empty, &mut |a, b| {
            calls += 1;
            a.cmp(b)
        });
        let mut one = vec![7_u8];
        sort_by_dyn(&mut one, &mut |a, b| {
            calls += 1;
            a.cmp(b)
        });
        assert!(empty.is_empty(), "an empty slice must stay empty");
        assert_eq!(one, vec![7], "a one-element slice must not change");
        assert_eq!(calls, 0, "no comparison is needed below two elements");
    }

    /// Zero-sized elements sort without touching memory, and the count holds.
    #[test]
    fn zero_sized_elements_keep_their_count() {
        let mut units = vec![(); 100];
        sort_by_dyn(&mut units, &mut |a, b| a.cmp(b));
        assert_eq!(units.len(), 100, "sorting must not change the length");
    }

    /// A large element type (wider than the sort's small-buffer heuristics)
    /// sorts exactly as `sort_by` does, payload included.
    ///
    /// `unnecessary_sort_by` is allowed for the reason given above
    /// `it_keeps_equal_elements_in_their_original_order`: the baseline is
    /// `sort_by` itself.
    #[test]
    #[allow(clippy::unnecessary_sort_by)]
    fn wide_elements_sort_like_sort_by() {
        let input: Vec<(u8, [u64; 16])> = (0..300_u64)
            .map(|i| (((i * 7919) % 13) as u8, [i; 16]))
            .collect();
        let mut expected = input.clone();
        expected.sort_by(|a, b| a.0.cmp(&b.0));
        let mut got = input;
        sort_by_dyn(&mut got, &mut |a, b| a.0.cmp(&b.0));
        assert_eq!(
            got, expected,
            "wide elements must land where sort_by puts them"
        );
    }

    /// Owned heap values move, they are not copied or dropped twice: every
    /// string is still there once, in `sort_by`'s order.
    #[test]
    fn owned_strings_sort_like_sort_by() {
        let input: Vec<String> = (0..500_u32)
            .map(|i| format!("{:03}-{i}", (i * 37) % 101))
            .collect();
        let mut expected = input.clone();
        expected.sort_by(|a, b| a[..3].cmp(&b[..3]));
        let mut got = input;
        sort_by_dyn(&mut got, &mut |a, b| a[..3].cmp(&b[..3]));
        assert_eq!(got, expected, "strings must land where sort_by puts them");
    }

    /// Already sorted, reversed and all-equal inputs: the shapes a sort
    /// special-cases, each above the small-sort threshold.
    ///
    /// `unnecessary_sort_by` is allowed: the baseline is `sort_by` itself.
    #[test]
    #[allow(clippy::unnecessary_sort_by)]
    fn presorted_reversed_and_equal_inputs_match_sort_by() {
        let n = 2_000_u32;
        let shapes: [Vec<(u32, u32)>; 3] = [
            (0..n).map(|i| (i, i)).collect(),
            (0..n).rev().map(|i| (i, i)).collect(),
            (0..n).map(|i| (5, i)).collect(),
        ];
        for input in shapes {
            let mut expected = input.clone();
            expected.sort_by(|a, b| a.0.cmp(&b.0));
            let mut got = input;
            sort_by_dyn(&mut got, &mut |a, b| a.0.cmp(&b.0));
            assert_eq!(got, expected, "a special-cased input shape reordered");
        }
    }

    /// A comparator that panics leaves the caller's slice as it was: the
    /// order is computed on indices before any element moves.
    #[test]
    fn a_panicking_comparator_leaves_the_slice_unchanged() {
        let input: Vec<u32> = (0..50).rev().collect();
        let mut got = input.clone();
        let mut calls = 0usize;
        // catch_unwind: the comparator's panic is the input under test, caught
        // so the test can read the slice the panic left behind.
        let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            sort_by_dyn(&mut got, &mut |a, b| {
                calls += 1;
                assert!(calls < 20, "comparator gives up");
                a.cmp(b)
            });
        }));
        assert!(
            unwound.is_err(),
            "the comparator's panic must reach the caller"
        );
        assert_eq!(got, input, "no element may move before the order is known");
    }

    proptest::proptest! {
        /// Any input, any key width: the same order as `sort_by`, equal keys
        /// in arrival order (the second field records arrival).
        /// `unnecessary_sort_by` is allowed: the baseline is `sort_by` itself.
        #[test]
        #[allow(clippy::unnecessary_sort_by)]
        fn any_input_sorts_like_sort_by(
            keys in proptest::collection::vec(0_u8..8, 0..400),
        ) {
            let input: Vec<(u8, usize)> = keys.into_iter().enumerate().map(|(i, k)| (k, i)).collect();
            let mut expected = input.clone();
            expected.sort_by(|a, b| a.0.cmp(&b.0));
            let mut got = input;
            sort_by_dyn(&mut got, &mut |a, b| a.0.cmp(&b.0));
            proptest::prop_assert_eq!(got, expected, "sort_by_dyn must match sort_by");
        }

        /// `apply_order` with any permutation places element `order[i]` at `i`.
        #[test]
        fn apply_order_follows_any_permutation(
            order in proptest::strategy::Just((0..64_usize).collect::<Vec<_>>()).prop_shuffle(),
        ) {
            let original: Vec<usize> = (100..164).collect();
            let mut got = original.clone();
            apply_order(&mut got, order.clone());
            let want: Vec<usize> = order.iter().map(|&i| original[i]).collect();
            proptest::prop_assert_eq!(got, want, "permutation {:?} misapplied", order);
        }
    }
}
