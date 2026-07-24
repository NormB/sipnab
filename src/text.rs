// SPDX-License-Identifier: MIT OR Apache-2.0

//! Small UTF-8 text helpers shared across output and TUI code.
//!
//! Byte-offset arithmetic (display truncation, cursor math, payload limits)
//! can land in the middle of a multibyte UTF-8 sequence, and slicing a `str`
//! there panics. The helpers here make such offsets safe to slice with.

/// Largest index `<= index` that lies on a `char` boundary of `s`.
///
/// Stable-Rust stand-in for the unstable `str::floor_char_boundary`: backs an
/// arbitrary byte offset up to the previous character boundary so it can be
/// used as a slice endpoint. Indexes at or past `s.len()` clamp to `s.len()`.
pub fn floor_char_boundary(s: &str, index: usize) -> usize {
    if index >= s.len() {
        return s.len();
    }
    let mut i = index;
    while i > 0 && !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Boundary indexes are returned unchanged; mid-character indexes back
    /// up; past-the-end indexes clamp to the string length.
    #[test]
    fn floor_char_boundary_clamps_and_backs_up() {
        let s = "aé漢"; // 'a' 1 byte, 'é' 2 bytes, '漢' 3 bytes
        assert_eq!(floor_char_boundary(s, 0), 0);
        assert_eq!(floor_char_boundary(s, 1), 1); // start of 'é'
        assert_eq!(floor_char_boundary(s, 2), 1); // inside 'é'
        assert_eq!(floor_char_boundary(s, 3), 3); // start of '漢'
        assert_eq!(floor_char_boundary(s, 4), 3); // inside '漢'
        assert_eq!(floor_char_boundary(s, 5), 3); // inside '漢'
        assert_eq!(floor_char_boundary(s, 6), 6); // == len
        assert_eq!(floor_char_boundary(s, 100), 6); // past the end
        assert_eq!(floor_char_boundary("", 5), 0);
    }
}
