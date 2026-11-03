// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! Opening the per-CPU perf rings: no kernel, no `aya`, always tested.
//!
//! Split from the loader for the reason `bpf_record` is: the loader compiles
//! only with the `bpf` feature, which `--features full` (the local hook) does
//! not enable, so a test beside it would run in CI and never in the hook.
//! Nothing here needs `aya`; the loader passes its real open and publish calls.

use std::io;

/// Pages in each per-CPU ring.
///
/// Two, the size `aya` 0.14 chose when it was given none. From 0.15 the count
/// is an argument, and `aya` refuses one that is not a power of two -- but only
/// when it opens the ring, on a kernel with BTF, which is no machine this
/// project builds on.
pub const RING_PAGES: usize = 2;

/// Open one ring per CPU and publish each in `EVENTS` at that CPU's index.
///
/// Two steps since `aya` 0.15, which used to be one: `PerfEventArray::open`
/// did both. A ring that is opened and never published is read forever and
/// never written, because the kernel finds no event at that CPU's index and
/// drops the record, so publishing is not left to the caller to remember.
///
/// `open` and `publish` are arguments so the order and the refusals can be
/// tested without a kernel: the real ones need `CAP_BPF` and BTF.
///
/// # Errors
///
/// A ring that cannot be opened or published fails the whole attach, naming
/// its CPU, and so does a machine that reports no CPU at all: a capture that
/// reads from no ring reads exactly like quiet traffic.
pub fn open_rings<B>(
    cpus: impl IntoIterator<Item = u32>,
    mut open: impl FnMut(u32) -> io::Result<B>,
    mut publish: impl FnMut(u32, &B) -> io::Result<()>,
) -> io::Result<Vec<B>> {
    let mut rings = Vec::new();
    for cpu in cpus {
        let ring = open(cpu)
            .map_err(|e| io::Error::other(format!("opening the ring for cpu {cpu}: {e}")))?;
        publish(cpu, &ring)
            .map_err(|e| io::Error::other(format!("publishing the ring for cpu {cpu}: {e}")))?;
        rings.push(ring);
    }
    if rings.is_empty() {
        return Err(io::Error::other(
            "no per-CPU ring could be opened, so nothing would ever be read",
        ));
    }
    Ok(rings)
}

#[cfg(test)]
mod tests {
    use super::*;
    type TestError = Box<dyn std::error::Error>;

    /// Every ring opened is published, at its own CPU's index.
    ///
    /// Since aya 0.15 opening a ring and publishing it in `EVENTS` are two
    /// calls. A ring that is opened and never published is read forever and
    /// never written: the kernel's `bpf_perf_event_output` finds no event at
    /// that CPU's index and drops the record, and nothing reports an error.
    #[test]
    fn every_opened_ring_is_published_at_its_own_cpu() -> Result<(), TestError> {
        let mut published = Vec::new();
        let rings = open_rings(
            [0, 2, 5],
            |cpu| Ok(cpu * 10),
            |cpu, ring: &u32| {
                published.push((cpu, *ring));
                Ok(())
            },
        )?;
        assert_eq!(
            rings,
            vec![0, 20, 50],
            "one ring per CPU, in CPU order, as `open` returned them"
        );
        assert_eq!(
            published,
            vec![(0, 0), (2, 20), (5, 50)],
            "every opened ring is published at its own CPU's index"
        );
        Ok(())
    }

    /// A ring that cannot be published fails the attach, naming the CPU.
    ///
    /// Skipping it would leave that CPU's records dropped in the kernel while
    /// the capture reported itself attached.
    #[test]
    fn a_ring_that_cannot_be_published_fails_the_attach() -> Result<(), TestError> {
        let result = open_rings([0, 1], Ok, |cpu, _: &u32| {
            if cpu == 1 {
                Err(io::Error::other("map full"))
            } else {
                Ok(())
            }
        });
        let e = result.err().ok_or("a failed publish was skipped")?;
        let text = e.to_string();
        assert!(
            text.contains("cpu 1") && text.contains("map full"),
            "{text}"
        );
        Ok(())
    }

    /// A ring that cannot be opened fails the attach, naming the CPU.
    #[test]
    fn a_ring_that_cannot_be_opened_fails_the_attach() -> Result<(), TestError> {
        let result = open_rings(
            [3],
            |_| Err::<u32, _>(io::Error::other("no perf events")),
            |_, _: &u32| Ok(()),
        );
        let e = result.err().ok_or("a failed open was skipped")?;
        let text = e.to_string();
        assert!(
            text.contains("cpu 3") && text.contains("no perf events"),
            "{text}"
        );
        Ok(())
    }

    /// No CPU at all is refused rather than read as a quiet capture.
    #[test]
    fn no_cpus_is_refused() {
        let result = open_rings([], Ok, |_, _: &u32| Ok(()));
        assert!(
            result.is_err(),
            "no ring was opened, so nothing would be read"
        );
    }

    /// aya refuses a ring size that is not a power of two, and only when it
    /// opens the ring on a BTF kernel; this holds the count where every build
    /// can see it.
    #[test]
    fn the_ring_page_count_is_one_aya_accepts() {
        let pages = std::hint::black_box(RING_PAGES);
        assert!(
            pages.is_power_of_two(),
            "{pages} pages is not a power of two"
        );
    }
}
