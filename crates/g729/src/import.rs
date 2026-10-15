// SPDX-License-Identifier: MIT OR Apache-2.0

//! Build the table file from the ITU-T G.729 software package.
//!
//! [`import_from_itu`] accepts the package zip, or a directory holding files
//! extracted from it, and locates each source file it needs by the sha256
//! pinned in [`crate::tables::SOURCES`]; names and paths are not trusted. From
//! each file it reads only the line range recorded for an entry, removes C
//! comments, and collects the integer literals: for a table, those after the
//! first `=`; for a scalar, the literal at the recorded position. Nothing is
//! compiled or run. The second SID LSF MA predictor, which the reference
//! computes at run time, is computed from equation (B.18)
//! ([`crate::tables::b18_mix`]). The result must hash to
//! [`crate::tables::VALUES_SHA256`], or nothing is returned.

use std::collections::BTreeMap;
use std::path::Path;
use std::string::{String, ToString};
use std::vec::Vec;

use sha2::{Digest, Sha256};

use crate::table_file::{encode, values_sha256};
use crate::tables::{ENTRIES, SOURCES, Source, VALUES_SHA256, b18_mix, source};

/// Why the import failed.
#[derive(Debug)]
pub enum ImportError {
    /// The path, or a file or directory below it, could not be read.
    Io(std::io::Error),
    /// The path is a file but not a readable zip archive.
    Zip(String),
    /// A source file the importer needs is not in the package: no file in it
    /// has the pinned sha256. The package is another release, or a modified
    /// or incomplete copy.
    MissingSource {
        /// Its path below `Software/G729_Release3/`.
        file: &'static str,
        /// Its pinned sha256.
        sha256: &'static str,
    },
    /// An entry's line range does not hold the expected number of integers,
    /// or holds one outside the 16-bit range. Not expected from a package
    /// whose files match the pinned hashes.
    Shape {
        /// The entry.
        name: String,
        /// Integers expected.
        expected: usize,
        /// Integers found.
        found: usize,
    },
    /// An entry of the layout has no locator in the package. Not expected:
    /// it would be a defect in this crate.
    UnknownEntry(String),
    /// The imported values do not hash to
    /// [`VALUES_SHA256`]; the string is the hash
    /// they have. Nothing is returned.
    ValuesHash(String),
}

impl core::fmt::Display for ImportError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "cannot read the ITU package: {e}"),
            Self::Zip(e) => write!(f, "cannot read the ITU package zip: {e}"),
            Self::MissingSource { file, sha256 } => {
                write!(
                    f,
                    "ITU source {file} (sha256 {sha256}) not found in the package"
                )
            }
            Self::Shape {
                name,
                expected,
                found,
            } => {
                write!(f, "{name}: expected {expected} integers, found {found}")
            }
            Self::UnknownEntry(name) => write!(f, "no table entry named {name}"),
            Self::ValuesHash(got) => {
                write!(f, "imported values hash {got}, expected {VALUES_SHA256}")
            }
        }
    }
}

impl std::error::Error for ImportError {}

impl From<std::io::Error> for ImportError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// The source files of a package, keyed by sha256 (only pinned ones kept).
struct Package {
    files: BTreeMap<&'static str, Vec<u8>>,
}

fn pinned_hashes() -> Vec<&'static str> {
    let mut v: Vec<&'static str> = SOURCES.iter().map(|(_, s)| s.sha256).collect();
    v.sort_unstable();
    v.dedup();
    v
}

fn sha256_hex(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    let mut s = String::with_capacity(64);
    for b in digest {
        s.push(char::from(b"0123456789abcdef"[usize::from(b >> 4)]));
        s.push(char::from(b"0123456789abcdef"[usize::from(b & 15)]));
    }
    s
}

impl Package {
    fn open(path: &Path) -> Result<Self, ImportError> {
        let wanted = pinned_hashes();
        let mut files = BTreeMap::new();
        let mut keep = |data: Vec<u8>| {
            let h = sha256_hex(&data);
            if let Some(&pin) = wanted.iter().find(|w| **w == h) {
                files.insert(pin, data);
            }
        };
        if path.is_dir() {
            let mut stack = std::vec![path.to_path_buf()];
            while let Some(dir) = stack.pop() {
                for entry in std::fs::read_dir(&dir)? {
                    let p = entry?.path();
                    if p.is_dir() {
                        stack.push(p);
                    } else if p.is_file() {
                        keep(std::fs::read(&p)?);
                    }
                }
            }
        } else {
            let file = std::fs::File::open(path)?;
            let mut zip =
                zip::ZipArchive::new(file).map_err(|e| ImportError::Zip(e.to_string()))?;
            for i in 0..zip.len() {
                let mut entry = zip
                    .by_index(i)
                    .map_err(|e| ImportError::Zip(e.to_string()))?;
                if !entry.is_file() {
                    continue;
                }
                let mut data = Vec::new();
                std::io::Read::read_to_end(&mut entry, &mut data)?;
                keep(data);
            }
        }
        Ok(Package { files })
    }

    fn lines(&self, src: &Source) -> Result<String, ImportError> {
        let data = self
            .files
            .get(src.sha256)
            .ok_or(ImportError::MissingSource {
                file: src.file,
                sha256: src.sha256,
            })?;
        // The sources are 8-bit text; map bytes one to one.
        let text: String = data.iter().map(|&b| char::from(b)).collect();
        let first = src.first_line as usize;
        let last = src.last_line as usize;
        Ok(text
            .split('\n')
            .skip(first - 1)
            .take(last + 1 - first)
            .collect::<Vec<_>>()
            .join("\n"))
    }

    fn integers(&self, name: &str) -> Result<Vec<i32>, ImportError> {
        let src = source(name).ok_or_else(|| ImportError::UnknownEntry(name.to_string()))?;
        let text = strip_comments(&self.lines(src)?);
        let body = match (src.token, text.find('=')) {
            (None, Some(eq)) => &text[eq + 1..],
            _ => &text[..],
        };
        Ok(integer_literals(body))
    }

    /// The values of one entry: all integers of a table, or one of a scalar.
    fn entry(&self, name: &str, len: usize) -> Result<Vec<i16>, ImportError> {
        let src = source(name).ok_or_else(|| ImportError::UnknownEntry(name.to_string()))?;
        let ints = self.integers(name)?;
        let picked: Vec<i32> = match src.token {
            Some(k) => ints.get(k).copied().into_iter().collect(),
            None => ints,
        };
        if picked.len() != len || picked.iter().any(|&v| i16::try_from(v).is_err()) {
            return Err(ImportError::Shape {
                name: name.to_string(),
                expected: len,
                found: picked.len(),
            });
        }
        Ok(picked.into_iter().map(|v| v as i16).collect())
    }
}

/// Remove `/* */` and `//` comments.
fn strip_comments(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'/' && b.get(i + 1) == Some(&b'*') {
            i += 2;
            while i < b.len() && !(b[i] == b'*' && b.get(i + 1) == Some(&b'/')) {
                i += 1;
            }
            i += 2;
            out.push(' ');
        } else if b[i] == b'/' && b.get(i + 1) == Some(&b'/') {
            while i < b.len() && b[i] != b'\n' {
                i += 1;
            }
        } else {
            out.push(char::from(b[i]));
            i += 1;
        }
    }
    out
}

fn is_word(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_' || c == b'.'
}

/// The integer literals of C text: decimal or hexadecimal digits not touching
/// a letter, digit, `_` or `.` on either side, with an optional leading minus
/// (whitespace allowed after it) that does not itself follow such a
/// character. Digits inside identifiers, suffixed literals or floating-point
/// literals are therefore not read.
pub(crate) fn integer_literals(s: &str) -> Vec<i32> {
    let bytes = s.as_bytes();
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < bytes.len() {
        let ch = bytes[pos];
        if ch.is_ascii_alphabetic() || ch == b'_' {
            while pos < bytes.len() && is_word(bytes[pos]) {
                pos += 1;
            }
            continue;
        }
        if !ch.is_ascii_digit() || (pos > 0 && is_word(bytes[pos - 1])) {
            pos += 1;
            continue;
        }
        let start = pos;
        let (radix, digits_from) = if ch == b'0' && matches!(bytes.get(pos + 1), Some(b'x' | b'X'))
        {
            (16, pos + 2)
        } else {
            (10, pos)
        };
        pos = digits_from;
        while pos < bytes.len() && (bytes[pos] as char).is_digit(radix) {
            pos += 1;
        }
        let digits = &s[digits_from..pos];
        if pos < bytes.len() && is_word(bytes[pos]) {
            // Part of a float, a suffixed literal or an identifier-like token.
            while pos < bytes.len() && is_word(bytes[pos]) {
                pos += 1;
            }
            continue;
        }
        let Ok(mut value) = i64::from_str_radix(digits, radix) else {
            continue;
        };
        let mut back = start;
        while back > 0 && bytes[back - 1].is_ascii_whitespace() {
            back -= 1;
        }
        if back > 0 && bytes[back - 1] == b'-' && !(back > 1 && is_word(bytes[back - 2])) {
            value = -value;
        }
        if let Ok(value) = i32::try_from(value) {
            out.push(value);
        }
    }
    out
}

/// Import the user-supplied tables from the ITU package at `path` (the zip,
/// or a directory of files extracted from it) and return the table file.
///
/// The bytes returned are a complete table file, [`FILE_LEN`](crate::FILE_LEN)
/// bytes long, that [`Tables::from_bytes`](crate::Tables::from_bytes) loads.
/// Write them to a file once and load that file on each start; the import
/// reads the whole package.
///
/// # Errors
///
/// - [`ImportError::Io`]: `path` or a file below it cannot be read.
/// - [`ImportError::Zip`]: `path` is a file that is not a readable zip.
/// - [`ImportError::MissingSource`]: a needed source file, found by its
///   pinned sha256, is not in the package.
/// - [`ImportError::Shape`] or [`ImportError::UnknownEntry`]: an entry could
///   not be read as recorded. Not expected from a package whose files match
///   the pinned hashes.
/// - [`ImportError::ValuesHash`]: the values read do not hash to
///   [`VALUES_SHA256`].
///
/// # Panics
///
/// Does not panic.
///
/// # Examples
///
/// ```no_run
/// // The zip downloaded from the ITU-T, or a directory extracted from it.
/// let table_file = g729::import_from_itu(std::path::Path::new(
///     "T-REC-G.729-201206-I!!SOFT-ZST-E.zip",
/// ))?;
/// std::fs::write("g729-tables.bin", &table_file)?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn import_from_itu(path: &Path) -> Result<Vec<u8>, ImportError> {
    let pkg = Package::open(path)?;
    let mut values: Vec<i16> = Vec::new();
    let mut ma: Option<Vec<i16>> = None;
    for entry in ENTRIES {
        if entry.name == "sid_lsf_ma_predictor" {
            let p = ma
                .as_deref()
                .ok_or_else(|| ImportError::UnknownEntry(entry.name.to_string()))?;
            values.extend(sid_predictor(p));
            continue;
        }
        let v = pkg.entry(entry.name, entry.len)?;
        if entry.name == "lsp_ma_predictor" {
            ma = Some(v.clone());
        }
        values.extend(v);
    }
    let got = values_sha256(values.iter().copied());
    if got != VALUES_SHA256 {
        return Err(ImportError::ValuesHash(got));
    }
    Ok(encode(&values))
}

/// Equation (B.18) over the flattened main predictors.
fn sid_predictor(ma: &[i16]) -> Vec<i16> {
    let mut p = [[[0i16; 10]; 4]; 2];
    for (k, v) in ma.iter().enumerate().take(80) {
        p[k / 40][(k / 10) % 4][k % 10] = *v;
    }
    let mixed = b18_mix(&p[0], &p[1]);
    let mut out: Vec<i16> = p[0].as_flattened().to_vec();
    out.extend_from_slice(mixed.as_flattened());
    out
}

/// The integer literals the importer reads for `name` (a table's whole
/// initializer, or every literal of a scalar's line). For cross-checking the
/// formula tables and text constants against the reference; it returns
/// numbers only.
///
/// # Errors
///
/// [`ImportError::Io`], [`ImportError::Zip`] or [`ImportError::MissingSource`]
/// as for [`import_from_itu`]; [`ImportError::UnknownEntry`] when `name` has
/// no locator in [`SOURCES`].
///
/// # Panics
///
/// Does not panic.
pub fn reference_values(path: &Path, name: &str) -> Result<Vec<i32>, ImportError> {
    Package::open(path)?.integers(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literals_skip_identifiers_floats_and_comments() {
        let s = strip_comments("Word16 tab[3] = { 1, -2, 0x10 }; /* 99 */ // 7\n x2 = 1.5;");
        assert_eq!(integer_literals(&s), std::vec![3, 1, -2, 16]);
        assert_eq!(
            integer_literals("a - 5, b-3, -\t4, 7L, 9"),
            std::vec![-5, 3, -4, 9]
        );
    }
}
