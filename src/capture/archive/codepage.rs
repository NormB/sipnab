// SPDX-License-Identifier: MIT OR Apache-2.0

//! The three single-byte code pages a ZIP password may have been typed in.
//!
//! A ZIP decryptor has to reproduce the exact bytes the archive's creator
//! hashed, and the format never recorded which encoding that was. Info-ZIP's
//! `unzip` and 7-Zip fall back to the OEM code page of a DOS or Windows
//! console, so a password typed as `ü` on a German Windows box is the single
//! byte `0x81` (CP437 and CP850), or `0xfc` (CP1252), rather than UTF-8's two.
//!
//! The tables are the upper halves of the code pages as Python's `codecs`
//! module defines them; the lower half of each is ASCII. They were generated,
//! not typed, and `tests` pins the characters that tell the three apart.

/// The upper half of CP437: the character each byte 0x80..=0xFF stands for.
const CP437_HIGH: [Option<char>; 128] = [
    Some('\u{00c7}'),
    Some('\u{00fc}'),
    Some('\u{00e9}'),
    Some('\u{00e2}'),
    Some('\u{00e4}'),
    Some('\u{00e0}'),
    Some('\u{00e5}'),
    Some('\u{00e7}'),
    Some('\u{00ea}'),
    Some('\u{00eb}'),
    Some('\u{00e8}'),
    Some('\u{00ef}'),
    Some('\u{00ee}'),
    Some('\u{00ec}'),
    Some('\u{00c4}'),
    Some('\u{00c5}'),
    Some('\u{00c9}'),
    Some('\u{00e6}'),
    Some('\u{00c6}'),
    Some('\u{00f4}'),
    Some('\u{00f6}'),
    Some('\u{00f2}'),
    Some('\u{00fb}'),
    Some('\u{00f9}'),
    Some('\u{00ff}'),
    Some('\u{00d6}'),
    Some('\u{00dc}'),
    Some('\u{00a2}'),
    Some('\u{00a3}'),
    Some('\u{00a5}'),
    Some('\u{20a7}'),
    Some('\u{0192}'),
    Some('\u{00e1}'),
    Some('\u{00ed}'),
    Some('\u{00f3}'),
    Some('\u{00fa}'),
    Some('\u{00f1}'),
    Some('\u{00d1}'),
    Some('\u{00aa}'),
    Some('\u{00ba}'),
    Some('\u{00bf}'),
    Some('\u{2310}'),
    Some('\u{00ac}'),
    Some('\u{00bd}'),
    Some('\u{00bc}'),
    Some('\u{00a1}'),
    Some('\u{00ab}'),
    Some('\u{00bb}'),
    Some('\u{2591}'),
    Some('\u{2592}'),
    Some('\u{2593}'),
    Some('\u{2502}'),
    Some('\u{2524}'),
    Some('\u{2561}'),
    Some('\u{2562}'),
    Some('\u{2556}'),
    Some('\u{2555}'),
    Some('\u{2563}'),
    Some('\u{2551}'),
    Some('\u{2557}'),
    Some('\u{255d}'),
    Some('\u{255c}'),
    Some('\u{255b}'),
    Some('\u{2510}'),
    Some('\u{2514}'),
    Some('\u{2534}'),
    Some('\u{252c}'),
    Some('\u{251c}'),
    Some('\u{2500}'),
    Some('\u{253c}'),
    Some('\u{255e}'),
    Some('\u{255f}'),
    Some('\u{255a}'),
    Some('\u{2554}'),
    Some('\u{2569}'),
    Some('\u{2566}'),
    Some('\u{2560}'),
    Some('\u{2550}'),
    Some('\u{256c}'),
    Some('\u{2567}'),
    Some('\u{2568}'),
    Some('\u{2564}'),
    Some('\u{2565}'),
    Some('\u{2559}'),
    Some('\u{2558}'),
    Some('\u{2552}'),
    Some('\u{2553}'),
    Some('\u{256b}'),
    Some('\u{256a}'),
    Some('\u{2518}'),
    Some('\u{250c}'),
    Some('\u{2588}'),
    Some('\u{2584}'),
    Some('\u{258c}'),
    Some('\u{2590}'),
    Some('\u{2580}'),
    Some('\u{03b1}'),
    Some('\u{00df}'),
    Some('\u{0393}'),
    Some('\u{03c0}'),
    Some('\u{03a3}'),
    Some('\u{03c3}'),
    Some('\u{00b5}'),
    Some('\u{03c4}'),
    Some('\u{03a6}'),
    Some('\u{0398}'),
    Some('\u{03a9}'),
    Some('\u{03b4}'),
    Some('\u{221e}'),
    Some('\u{03c6}'),
    Some('\u{03b5}'),
    Some('\u{2229}'),
    Some('\u{2261}'),
    Some('\u{00b1}'),
    Some('\u{2265}'),
    Some('\u{2264}'),
    Some('\u{2320}'),
    Some('\u{2321}'),
    Some('\u{00f7}'),
    Some('\u{2248}'),
    Some('\u{00b0}'),
    Some('\u{2219}'),
    Some('\u{00b7}'),
    Some('\u{221a}'),
    Some('\u{207f}'),
    Some('\u{00b2}'),
    Some('\u{25a0}'),
    Some('\u{00a0}'),
];

/// The upper half of CP850: the character each byte 0x80..=0xFF stands for.
const CP850_HIGH: [Option<char>; 128] = [
    Some('\u{00c7}'),
    Some('\u{00fc}'),
    Some('\u{00e9}'),
    Some('\u{00e2}'),
    Some('\u{00e4}'),
    Some('\u{00e0}'),
    Some('\u{00e5}'),
    Some('\u{00e7}'),
    Some('\u{00ea}'),
    Some('\u{00eb}'),
    Some('\u{00e8}'),
    Some('\u{00ef}'),
    Some('\u{00ee}'),
    Some('\u{00ec}'),
    Some('\u{00c4}'),
    Some('\u{00c5}'),
    Some('\u{00c9}'),
    Some('\u{00e6}'),
    Some('\u{00c6}'),
    Some('\u{00f4}'),
    Some('\u{00f6}'),
    Some('\u{00f2}'),
    Some('\u{00fb}'),
    Some('\u{00f9}'),
    Some('\u{00ff}'),
    Some('\u{00d6}'),
    Some('\u{00dc}'),
    Some('\u{00f8}'),
    Some('\u{00a3}'),
    Some('\u{00d8}'),
    Some('\u{00d7}'),
    Some('\u{0192}'),
    Some('\u{00e1}'),
    Some('\u{00ed}'),
    Some('\u{00f3}'),
    Some('\u{00fa}'),
    Some('\u{00f1}'),
    Some('\u{00d1}'),
    Some('\u{00aa}'),
    Some('\u{00ba}'),
    Some('\u{00bf}'),
    Some('\u{00ae}'),
    Some('\u{00ac}'),
    Some('\u{00bd}'),
    Some('\u{00bc}'),
    Some('\u{00a1}'),
    Some('\u{00ab}'),
    Some('\u{00bb}'),
    Some('\u{2591}'),
    Some('\u{2592}'),
    Some('\u{2593}'),
    Some('\u{2502}'),
    Some('\u{2524}'),
    Some('\u{00c1}'),
    Some('\u{00c2}'),
    Some('\u{00c0}'),
    Some('\u{00a9}'),
    Some('\u{2563}'),
    Some('\u{2551}'),
    Some('\u{2557}'),
    Some('\u{255d}'),
    Some('\u{00a2}'),
    Some('\u{00a5}'),
    Some('\u{2510}'),
    Some('\u{2514}'),
    Some('\u{2534}'),
    Some('\u{252c}'),
    Some('\u{251c}'),
    Some('\u{2500}'),
    Some('\u{253c}'),
    Some('\u{00e3}'),
    Some('\u{00c3}'),
    Some('\u{255a}'),
    Some('\u{2554}'),
    Some('\u{2569}'),
    Some('\u{2566}'),
    Some('\u{2560}'),
    Some('\u{2550}'),
    Some('\u{256c}'),
    Some('\u{00a4}'),
    Some('\u{00f0}'),
    Some('\u{00d0}'),
    Some('\u{00ca}'),
    Some('\u{00cb}'),
    Some('\u{00c8}'),
    Some('\u{0131}'),
    Some('\u{00cd}'),
    Some('\u{00ce}'),
    Some('\u{00cf}'),
    Some('\u{2518}'),
    Some('\u{250c}'),
    Some('\u{2588}'),
    Some('\u{2584}'),
    Some('\u{00a6}'),
    Some('\u{00cc}'),
    Some('\u{2580}'),
    Some('\u{00d3}'),
    Some('\u{00df}'),
    Some('\u{00d4}'),
    Some('\u{00d2}'),
    Some('\u{00f5}'),
    Some('\u{00d5}'),
    Some('\u{00b5}'),
    Some('\u{00fe}'),
    Some('\u{00de}'),
    Some('\u{00da}'),
    Some('\u{00db}'),
    Some('\u{00d9}'),
    Some('\u{00fd}'),
    Some('\u{00dd}'),
    Some('\u{00af}'),
    Some('\u{00b4}'),
    Some('\u{00ad}'),
    Some('\u{00b1}'),
    Some('\u{2017}'),
    Some('\u{00be}'),
    Some('\u{00b6}'),
    Some('\u{00a7}'),
    Some('\u{00f7}'),
    Some('\u{00b8}'),
    Some('\u{00b0}'),
    Some('\u{00a8}'),
    Some('\u{00b7}'),
    Some('\u{00b9}'),
    Some('\u{00b3}'),
    Some('\u{00b2}'),
    Some('\u{25a0}'),
    Some('\u{00a0}'),
];

/// The upper half of CP1252: the character each byte 0x80..=0xFF stands for.
/// `None` for the five bytes the code page leaves undefined.
const CP1252_HIGH: [Option<char>; 128] = [
    Some('\u{20ac}'),
    None,
    Some('\u{201a}'),
    Some('\u{0192}'),
    Some('\u{201e}'),
    Some('\u{2026}'),
    Some('\u{2020}'),
    Some('\u{2021}'),
    Some('\u{02c6}'),
    Some('\u{2030}'),
    Some('\u{0160}'),
    Some('\u{2039}'),
    Some('\u{0152}'),
    None,
    Some('\u{017d}'),
    None,
    None,
    Some('\u{2018}'),
    Some('\u{2019}'),
    Some('\u{201c}'),
    Some('\u{201d}'),
    Some('\u{2022}'),
    Some('\u{2013}'),
    Some('\u{2014}'),
    Some('\u{02dc}'),
    Some('\u{2122}'),
    Some('\u{0161}'),
    Some('\u{203a}'),
    Some('\u{0153}'),
    None,
    Some('\u{017e}'),
    Some('\u{0178}'),
    Some('\u{00a0}'),
    Some('\u{00a1}'),
    Some('\u{00a2}'),
    Some('\u{00a3}'),
    Some('\u{00a4}'),
    Some('\u{00a5}'),
    Some('\u{00a6}'),
    Some('\u{00a7}'),
    Some('\u{00a8}'),
    Some('\u{00a9}'),
    Some('\u{00aa}'),
    Some('\u{00ab}'),
    Some('\u{00ac}'),
    Some('\u{00ad}'),
    Some('\u{00ae}'),
    Some('\u{00af}'),
    Some('\u{00b0}'),
    Some('\u{00b1}'),
    Some('\u{00b2}'),
    Some('\u{00b3}'),
    Some('\u{00b4}'),
    Some('\u{00b5}'),
    Some('\u{00b6}'),
    Some('\u{00b7}'),
    Some('\u{00b8}'),
    Some('\u{00b9}'),
    Some('\u{00ba}'),
    Some('\u{00bb}'),
    Some('\u{00bc}'),
    Some('\u{00bd}'),
    Some('\u{00be}'),
    Some('\u{00bf}'),
    Some('\u{00c0}'),
    Some('\u{00c1}'),
    Some('\u{00c2}'),
    Some('\u{00c3}'),
    Some('\u{00c4}'),
    Some('\u{00c5}'),
    Some('\u{00c6}'),
    Some('\u{00c7}'),
    Some('\u{00c8}'),
    Some('\u{00c9}'),
    Some('\u{00ca}'),
    Some('\u{00cb}'),
    Some('\u{00cc}'),
    Some('\u{00cd}'),
    Some('\u{00ce}'),
    Some('\u{00cf}'),
    Some('\u{00d0}'),
    Some('\u{00d1}'),
    Some('\u{00d2}'),
    Some('\u{00d3}'),
    Some('\u{00d4}'),
    Some('\u{00d5}'),
    Some('\u{00d6}'),
    Some('\u{00d7}'),
    Some('\u{00d8}'),
    Some('\u{00d9}'),
    Some('\u{00da}'),
    Some('\u{00db}'),
    Some('\u{00dc}'),
    Some('\u{00dd}'),
    Some('\u{00de}'),
    Some('\u{00df}'),
    Some('\u{00e0}'),
    Some('\u{00e1}'),
    Some('\u{00e2}'),
    Some('\u{00e3}'),
    Some('\u{00e4}'),
    Some('\u{00e5}'),
    Some('\u{00e6}'),
    Some('\u{00e7}'),
    Some('\u{00e8}'),
    Some('\u{00e9}'),
    Some('\u{00ea}'),
    Some('\u{00eb}'),
    Some('\u{00ec}'),
    Some('\u{00ed}'),
    Some('\u{00ee}'),
    Some('\u{00ef}'),
    Some('\u{00f0}'),
    Some('\u{00f1}'),
    Some('\u{00f2}'),
    Some('\u{00f3}'),
    Some('\u{00f4}'),
    Some('\u{00f5}'),
    Some('\u{00f6}'),
    Some('\u{00f7}'),
    Some('\u{00f8}'),
    Some('\u{00f9}'),
    Some('\u{00fa}'),
    Some('\u{00fb}'),
    Some('\u{00fc}'),
    Some('\u{00fd}'),
    Some('\u{00fe}'),
    Some('\u{00ff}'),
];

/// A single-byte code page a ZIP password may be re-encoded into.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodePage {
    /// The original IBM PC code page, the DOS console default in the US.
    Cp437,
    /// DOS Latin-1, the console default across Western Europe.
    Cp850,
    /// Windows Latin-1, what a GUI tool on a Western Windows box types.
    Cp1252,
}

impl CodePage {
    /// Every code page, in the order a decryptor tries them.
    pub const ALL: [Self; 3] = [Self::Cp437, Self::Cp850, Self::Cp1252];

    /// The name an operator types after `--archive-password-encoding`.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Cp437 => "cp437",
            Self::Cp850 => "cp850",
            Self::Cp1252 => "cp1252",
        }
    }

    /// The table for bytes `0x80..=0xFF`.
    fn high(self) -> &'static [Option<char>; 128] {
        match self {
            Self::Cp437 => &CP437_HIGH,
            Self::Cp850 => &CP850_HIGH,
            Self::Cp1252 => &CP1252_HIGH,
        }
    }

    /// `text` in this code page, or `None` when a character has no byte here.
    ///
    /// Written into `out`, which the caller sizes in advance: one byte per
    /// character. A password is never grown into a reallocated buffer, because
    /// the copy a reallocation leaves behind is one `zeroize` cannot reach.
    #[must_use]
    pub fn encode_into(self, text: &str, out: &mut Vec<u8>) -> Option<()> {
        out.clear();
        for ch in text.chars() {
            if ch.is_ascii() {
                out.push(ch as u8);
                continue;
            }
            let at = self.high().iter().position(|c| *c == Some(ch))?;
            // `at` is below 128, so the sum is at most 0xFF.
            out.push(0x80 | at as u8);
        }
        Some(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enc(cp: CodePage, s: &str) -> Option<Vec<u8>> {
        let mut out = Vec::with_capacity(s.chars().count());
        cp.encode_into(s, &mut out).map(|()| out)
    }

    /// The characters where the three pages disagree, which is the only
    /// reason there are three: a table copied from the wrong page would
    /// still pass a test that only used ASCII.
    #[test]
    fn each_page_places_the_characters_that_tell_them_apart() {
        assert_eq!(enc(CodePage::Cp437, "\u{00fc}"), Some(vec![0x81]));
        assert_eq!(enc(CodePage::Cp850, "\u{00fc}"), Some(vec![0x81]));
        assert_eq!(enc(CodePage::Cp1252, "\u{00fc}"), Some(vec![0xfc]));
        // CP437 has the peseta sign where CP850 has the slashed o.
        assert_eq!(enc(CodePage::Cp437, "\u{20a7}"), Some(vec![0x9e]));
        assert_eq!(enc(CodePage::Cp850, "\u{00f8}"), Some(vec![0x9b]));
        assert_eq!(enc(CodePage::Cp437, "\u{00f8}"), None);
        // The euro sign exists only in CP1252.
        assert_eq!(enc(CodePage::Cp1252, "\u{20ac}"), Some(vec![0x80]));
        assert_eq!(enc(CodePage::Cp437, "\u{20ac}"), None);
    }

    #[test]
    fn ascii_passes_through_and_the_undefined_bytes_encode_nothing() {
        for cp in CodePage::ALL {
            assert_eq!(enc(cp, "abc 123"), Some(b"abc 123".to_vec()));
        }
        let undefined = CP1252_HIGH.iter().filter(|c| c.is_none()).count();
        assert_eq!(
            undefined, 5,
            "CP1252 leaves 0x81 0x8d 0x8f 0x90 0x9d undefined"
        );
    }
}
