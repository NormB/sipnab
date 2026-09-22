// SPDX-License-Identifier: MIT OR Apache-2.0

//! A minimal ustar writer for archive-input tests.
//!
//! The library carries its own test-only writer next to its reader, but that
//! one is `#[cfg(test)]` inside the crate and integration tests cannot reach
//! it. This is a second, independent writer — which is worth something in its
//! own right: a misreading of the format shared by a reader and the one writer
//! it was tested against would pass silently. The suite also reads archives the
//! system `tar` wrote, when one is installed, which neither writer can vouch
//! for.
#![allow(dead_code)]

/// One entry: a name, a ustar type flag, and data (written only for files).
pub struct Entry<'a> {
    /// The name exactly as it goes in the header. At most 100 bytes.
    pub name: &'a str,
    /// `b'0'` file, `b'5'` directory, `b'2'` symlink.
    pub typeflag: u8,
    /// File contents.
    pub data: &'a [u8],
}

impl<'a> Entry<'a> {
    /// A regular file.
    pub fn file(name: &'a str, data: &'a [u8]) -> Self {
        Self {
            name,
            typeflag: b'0',
            data,
        }
    }

    /// A directory.
    pub fn dir(name: &'a str) -> Self {
        Self {
            name,
            typeflag: b'5',
            data: &[],
        }
    }
}

/// Build a whole archive, end-of-archive marker included.
pub fn tar(entries: &[Entry<'_>]) -> Vec<u8> {
    let mut out = Vec::new();
    for e in entries {
        assert!(e.name.len() <= 100, "keep test names short: {}", e.name);
        let mut h = [0u8; 512];
        h[..e.name.len()].copy_from_slice(e.name.as_bytes());
        h[100..107].copy_from_slice(b"0000644");
        h[108..115].copy_from_slice(b"0001750");
        h[116..123].copy_from_slice(b"0001750");
        let size = if e.typeflag == b'0' { e.data.len() } else { 0 };
        h[124..135].copy_from_slice(format!("{size:011o}").as_bytes());
        h[136..147].copy_from_slice(b"14715254320");
        h[156] = e.typeflag;
        h[257..263].copy_from_slice(b"ustar\0");
        h[263..265].copy_from_slice(b"00");
        // Checksum over the header with its own field read as spaces.
        h[148..156].fill(b' ');
        let sum: u32 = h.iter().map(|&b| u32::from(b)).sum();
        h[148..155].copy_from_slice(format!("{sum:06o}\0").as_bytes());
        out.extend_from_slice(&h);
        if e.typeflag == b'0' {
            out.extend_from_slice(e.data);
            while !out.len().is_multiple_of(512) {
                out.push(0);
            }
        }
    }
    out.extend_from_slice(&[0u8; 1024]);
    out
}

/// gzip `data` with real compression.
pub fn gzip(data: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(data).expect("gzip");
    enc.finish().expect("gzip")
}
