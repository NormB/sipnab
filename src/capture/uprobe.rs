//! Deciding what a uprobe delivered may be used for.
//!
//! A kernel uprobe fetch argument is a **fixed** size chosen when the probe is
//! installed, but the write it observes is whatever length the application
//! passed. Those two disagree constantly, and the disagreement is not benign:
//! measured on a live OpenSIPS, a 512-byte fetch against a 128-byte SIP message
//! returned the message followed by 384 bytes of adjacent process heap —
//! pointers, not zeros. On a SIP proxy that heap can hold other calls'
//! plaintext.
//!
//! So the rule this module exists to enforce is: **only the bytes the
//! application actually wrote may ever leave here**, and everything past that
//! is wiped rather than merely ignored.
//!
//! Sizing is banded rather than maximal for the same reason. Several probes sit
//! on one symbol, each fetching one band and filtered to it, so what the kernel
//! delivers overshoots the true length by at most one band instead of by the
//! largest message sipnab supports. The band is a bound, not a guarantee, which
//! is why the truncation below still happens.

/// Fetch sizes, in bytes, for the banded probe set.
///
/// 64 is the kernel's hard ceiling for a single fetch argument — `x8[65]` is
/// refused — so every band above it is several arguments side by side. 2048 is
/// where that stops being accepted, and it covers an ordinary `INVITE` with SDP.
pub const BANDS: [usize; 4] = [64, 256, 1024, 2048];

/// The largest write the banded set can carry.
#[must_use]
pub fn max_fetch() -> usize {
    BANDS[BANDS.len() - 1]
}

/// The band that will carry a write of `len` bytes: the smallest that fits.
///
/// `None` when the write is larger than every band, which is not an error — it
/// is a message sipnab can only partially read, and the caller must say so
/// rather than presenting the fragment as whole.
#[must_use]
pub fn band_for(len: usize) -> Option<usize> {
    BANDS.iter().copied().find(|&b| len <= b)
}

/// The tracefs filter that confines a probe to its band.
///
/// The kernel evaluates this **before** recording the event — verified: a
/// 64-byte probe filtered to `len <= 64` delivered nothing at all for a
/// 128-byte write — which is what keeps an oversized fetch from reaching
/// userspace in the first place.
#[must_use]
pub fn filter_for(band: usize) -> String {
    let lower = BANDS.iter().copied().take_while(|&b| b < band).last();
    match lower {
        Some(prev) => format!("len > {prev} && len <= {band}"),
        None => format!("len > 0 && len <= {band}"),
    }
}

/// Plaintext a probe delivered, reduced to what may be used.
#[derive(Debug, PartialEq, Eq)]
pub struct Delivered {
    /// Exactly the bytes the application wrote, never the fetch padding.
    pub bytes: Vec<u8>,
    /// The write was longer than the largest band, so `bytes` is a prefix.
    ///
    /// Carried so a caller can refuse to treat a fragment as a whole message.
    /// A SIP message sipnab only half-read must never look like a complete one.
    pub truncated: bool,
}

/// Overwrite a buffer's tail so the fetch padding cannot outlive this call.
///
/// `write_volatile` rather than a plain loop or `fill`: the compiler is
/// entitled to delete stores to memory it can prove is never read again, which
/// is exactly this memory, and a wipe the optimiser removed is a wipe that
/// never happened.
fn wipe(buf: &mut [u8]) {
    for b in buf {
        // SAFETY: `b` is a valid, uniquely borrowed, writable byte.
        unsafe { std::ptr::write_volatile(b, 0) };
    }
}

/// Reduce one delivered event to the bytes that may be used, or reject it.
///
/// `raw` is the whole fetch, padding included. `len` is what the application
/// passed, straight from the probe. Returns `None` for anything that carries no
/// usable payload, so a caller cannot accidentally act on padding alone.
#[must_use]
pub fn accept(raw: &mut [u8], len: i32) -> Option<Delivered> {
    // A zero or negative length is an ordinary event, not a fault: TLS
    // libraries call the write path with nothing to send. It was the majority
    // of what the first traces returned, so filtering it is required rather
    // than tidy — the payload for these is entirely padding.
    let len = usize::try_from(len).ok().filter(|&n| n > 0)?;

    let usable = len.min(raw.len());
    let (keep, pad) = raw.split_at_mut(usable);
    wipe(pad);

    Some(Delivered {
        bytes: keep.to_vec(),
        // Truncated when the application wrote more than reached us, whether
        // because the write exceeded every band or because the fetch was short.
        truncated: len > usable,
    })
}

/// Whether delivered plaintext is worth carrying further.
///
/// These probes sit on every process mapping the library, so a filter is what
/// makes the feature affordable at all rather than an optimisation.
#[must_use]
pub fn is_interesting(bytes: &[u8]) -> bool {
    crate::sip::is_sip_message(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// THE rule. A short write inside a long fetch must yield the message and
    /// nothing else — the padding measured on a live proxy was adjacent heap.
    #[test]
    fn only_the_bytes_the_application_wrote_come_back() {
        let mut raw = vec![0xAA; 512];
        raw[..12].copy_from_slice(b"INVITE sip:x");

        let got = accept(&mut raw, 12).expect("a 12-byte write is usable");
        assert_eq!(got.bytes, b"INVITE sip:x");
        assert!(!got.truncated);
        assert_eq!(got.bytes.len(), 12, "never the 512-byte fetch");
    }

    /// Ignoring the padding is not enough: it must not survive in the buffer.
    #[test]
    fn the_padding_is_wiped_not_merely_skipped() {
        let mut raw = vec![0xAA; 128];
        raw[..4].copy_from_slice(b"SIP/");

        accept(&mut raw, 4).expect("usable");

        assert!(
            raw[4..].iter().all(|&b| b == 0),
            "adjacent process memory must not outlive the call that read it"
        );
        assert_eq!(&raw[..4], b"SIP/", "and the payload is left alone");
    }

    /// The zero-length writes were most of the first trace. They carry only
    /// padding, so acting on them would be acting on adjacent memory.
    #[test]
    fn a_zero_or_negative_length_write_is_rejected() {
        let mut raw = vec![0xAA; 64];
        assert_eq!(accept(&mut raw, 0), None, "zero-length carries no payload");
        assert_eq!(accept(&mut raw, -1), None, "a negative length is not one");
    }

    /// A message bigger than every band is a fragment, and must announce it.
    #[test]
    fn a_write_larger_than_the_fetch_is_reported_truncated() {
        let mut raw = vec![b'x'; max_fetch()];
        let got = accept(&mut raw, 9000).expect("still usable, just partial");

        assert_eq!(got.bytes.len(), max_fetch());
        assert!(
            got.truncated,
            "a half-read SIP message must never look like a complete one"
        );
    }

    /// Bands are chosen to overshoot as little as possible.
    #[test]
    fn the_smallest_band_that_fits_is_chosen() {
        assert_eq!(band_for(1), Some(64));
        assert_eq!(band_for(64), Some(64), "a band includes its own size");
        assert_eq!(
            band_for(65),
            Some(256),
            "one past a band moves up exactly one"
        );
        assert_eq!(band_for(2048), Some(2048));
        assert_eq!(band_for(2049), None, "larger than every band");
    }

    /// The filters must partition, or a write lands in two probes or none.
    #[test]
    fn the_band_filters_cover_every_length_exactly_once() {
        for len in 1..=max_fetch() {
            let matching: Vec<usize> = BANDS
                .iter()
                .copied()
                .filter(|&b| {
                    let lower = BANDS.iter().copied().take_while(|&x| x < b).last();
                    len > lower.unwrap_or(0) && len <= b
                })
                .collect();
            assert_eq!(
                matching.len(),
                1,
                "length {len} matched {matching:?}; bands must partition"
            );
        }
    }

    #[test]
    fn filter_text_matches_the_band_it_guards() {
        assert_eq!(filter_for(64), "len > 0 && len <= 64");
        assert_eq!(filter_for(256), "len > 64 && len <= 256");
        assert_eq!(filter_for(2048), "len > 1024 && len <= 2048");
    }

    /// These probes see every process on the box mapping the library.
    #[test]
    fn non_sip_plaintext_is_filtered_out() {
        assert!(is_interesting(b"INVITE sip:b@example.net SIP/2.0\r\n\r\n"));
        assert!(!is_interesting(b"GET /index.html HTTP/1.1\r\n\r\n"));
        assert!(!is_interesting(&[0u8; 32]));
    }
}
