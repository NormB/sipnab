// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! A counting allocator for the library's own test build.
//!
//! A test that pins how many allocations a hot path makes needs to observe
//! them, and the only place every allocation passes through is the global
//! allocator. This one forwards to the system allocator and counts, per
//! thread, how many allocations the CURRENT thread made, so tests running in
//! parallel on other threads cannot move a test's count.
//!
//! Only compiled in test builds (`#[cfg(test)] pub mod test_alloc;` in
//! `src/lib.rs`); the shipped binary keeps its own allocator (`src/main.rs`).
//! The `unsafe` census (`tests/support/unsafe_census.rs`) counts this file
//! as test code because of that declaration.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

thread_local! {
    /// Allocations (including reallocations) this thread has made.
    static ALLOCATIONS: Cell<u64> = const { Cell::new(0) };
}

/// The system allocator, counting each thread's allocations.
struct Counting;

// SAFETY: every call forwards to `System` with the caller's arguments
// unchanged; the only addition is a thread-local counter, which allocates
// nothing (a const-initialized `Cell` with no destructor).
unsafe impl GlobalAlloc for Counting {
    /// # Safety
    ///
    /// As [`GlobalAlloc::alloc`]: `layout` has a non-zero size.
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        bump();
        // SAFETY: forwarded unchanged; the caller upholds `alloc`'s contract.
        unsafe { System.alloc(layout) }
    }

    /// # Safety
    ///
    /// As [`GlobalAlloc::alloc_zeroed`]: `layout` has a non-zero size.
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        bump();
        // SAFETY: forwarded unchanged; the caller upholds the contract.
        unsafe { System.alloc_zeroed(layout) }
    }

    /// # Safety
    ///
    /// As [`GlobalAlloc::dealloc`]: `ptr` came from this allocator with this
    /// `layout`.
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: forwarded unchanged; `ptr` came from this allocator,
        // which is `System` underneath.
        unsafe { System.dealloc(ptr, layout) }
    }

    /// # Safety
    ///
    /// As [`GlobalAlloc::realloc`]: `ptr` came from this allocator with
    /// `layout`, and `new_size` is non-zero and does not overflow when
    /// rounded up to `layout`'s alignment.
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        bump();
        // SAFETY: forwarded unchanged; the caller upholds the contract.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

/// Count one allocation on this thread. `try_with`, because an allocation
/// can happen while the thread's locals are being torn down.
fn bump() {
    let _ = ALLOCATIONS.try_with(|n| n.set(n.get() + 1));
}

#[global_allocator]
static COUNTING: Counting = Counting;

/// How many allocations the current thread makes while running `f`, and
/// what `f` returned.
pub fn allocations_during<T>(f: impl FnOnce() -> T) -> (u64, T) {
    let before = ALLOCATIONS.with(Cell::get);
    let out = f();
    let after = ALLOCATIONS.with(Cell::get);
    (after - before, out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The counter sees an allocation made inside the closure, and nothing
    /// when the closure allocates nothing: a counter stuck at zero would
    /// make every allocation-count test pass.
    #[test]
    fn counts_this_threads_allocations_and_only_those() {
        let (none, ()) = allocations_during(|| {});
        assert_eq!(none, 0, "a closure that allocates nothing counts zero");
        let (one, v) = allocations_during(|| std::hint::black_box(vec![1u8; 32]));
        assert_eq!(one, 1, "one Vec is one allocation");
        assert_eq!(v.len(), 32, "the closure's value comes back");
    }
}
