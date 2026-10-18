// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! The table file: the user-supplied tables in a versioned binary layout.
//!
//! Layout, all integers little-endian:
//!
//! | Offset | Size | Field |
//! |---|---|---|
//! | 0 | 8 | magic `G729TBL\0` ([`FILE_MAGIC`]) |
//! | 8 | 2 | version, u16 ([`FILE_VERSION`]) |
//! | 10 | 2 | entry count, u16 (44) |
//! | 12 | ... | per entry of [`ENTRIES`], in order: index u16, value count u32, then the values as i16 |
//!
//! Nothing follows the last entry. The loader checks the magic, the version,
//! every entry's index and count against [`ENTRIES`], the total length, and
//! finally that the sha256 of the values (each as a little-endian i16, in file
//! order, headers excluded) equals [`VALUES_SHA256`]. Any other file is refused.

use std::vec::Vec;

use sha2::{Digest, Sha256};

use crate::tables::{ENTRIES, FILE_MAGIC, FILE_VERSION, Tables, VALUE_COUNT, VALUES_SHA256};

/// Why a table file was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TableError {
    /// The file does not start with [`FILE_MAGIC`]: it is not a table file.
    Magic,
    /// The file has another layout version (the value given). It was written
    /// for another release of this crate; build it again with
    /// [`import_from_itu`](crate::import_from_itu).
    Version(u16),
    /// The file is shorter or longer than the layout requires: it was
    /// truncated, or has bytes appended.
    Length {
        /// Bytes the layout requires.
        expected: usize,
        /// Bytes given.
        actual: usize,
    },
    /// The header declares another number of entries than [`ENTRIES`]
    /// holds: the file's layout is not this crate's.
    EntryCount {
        /// Entries the layout requires.
        expected: usize,
        /// Entries the file declares.
        actual: usize,
    },
    /// An entry header carries another entry's number: the file's layout is
    /// not this crate's.
    EntryNumber {
        /// Position of the entry header in the file.
        position: usize,
        /// The number it carries.
        actual: usize,
    },
    /// An entry header declares another value count than [`ENTRIES`]: the
    /// file's layout is not this crate's.
    Entry {
        /// Position of the entry.
        index: usize,
        /// Value count the layout requires.
        expected: usize,
        /// Value count the file declares.
        actual: usize,
    },
    /// The layout is right but the values do not hash to [`VALUES_SHA256`]:
    /// the file was changed, or built from another package.
    ValuesHash,
}

impl core::fmt::Display for TableError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Magic => write!(f, "not a G.729 table file (bad magic)"),
            Self::Version(v) => write!(f, "table file version {v}, expected {FILE_VERSION}"),
            Self::Length { expected, actual } => {
                write!(f, "table file is {actual} bytes, expected {expected}")
            }
            Self::EntryCount { expected, actual } => {
                write!(
                    f,
                    "table file declares {actual} entries, expected {expected}"
                )
            }
            Self::EntryNumber { position, actual } => write!(
                f,
                "table file entry {position} ({}) is numbered {actual}",
                ENTRIES.get(*position).map_or("?", |e| e.name)
            ),
            Self::Entry {
                index,
                expected,
                actual,
            } => write!(
                f,
                "table file entry {index} ({}) declares {actual} values, expected {expected}",
                ENTRIES.get(*index).map_or("?", |e| e.name)
            ),
            Self::ValuesHash => write!(
                f,
                "table values do not match the pinned sha256 {VALUES_SHA256}"
            ),
        }
    }
}

impl std::error::Error for TableError {}

/// Byte length of a valid table file.
pub const FILE_LEN: usize = 12 + ENTRIES.len() * 6 + VALUE_COUNT * 2;

/// Serialize values given in [`ENTRIES`] order into a table file.
pub(crate) fn encode(values: &[i16]) -> Vec<u8> {
    let mut out = Vec::with_capacity(FILE_LEN);
    out.extend_from_slice(FILE_MAGIC);
    out.extend_from_slice(&FILE_VERSION.to_le_bytes());
    out.extend_from_slice(&(ENTRIES.len() as u16).to_le_bytes());
    let mut at = 0;
    for (i, entry) in ENTRIES.iter().enumerate() {
        out.extend_from_slice(&(i as u16).to_le_bytes());
        out.extend_from_slice(&(entry.len as u32).to_le_bytes());
        for v in &values[at..at + entry.len] {
            out.extend_from_slice(&v.to_le_bytes());
        }
        at += entry.len;
    }
    out
}

/// sha256 of values as little-endian i16, lowercase hex.
pub(crate) fn values_sha256(values: impl IntoIterator<Item = i16>) -> std::string::String {
    let mut h = Sha256::new();
    for v in values {
        h.update(v.to_le_bytes());
    }
    hex(&h.finalize())
}

fn hex(bytes: &[u8]) -> std::string::String {
    use core::fmt::Write;
    let mut s = std::string::String::with_capacity(bytes.len() * 2);
    for b in bytes {
        // Writing to a String cannot fail.
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn u16_at(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

impl Tables {
    /// Load the tables from a table file, as written by
    /// [`import_from_itu`](crate::import_from_itu).
    ///
    /// Checks the magic, the layout version, every entry's index and value
    /// count, the total length ([`FILE_LEN`]), and finally that the sha256
    /// of the values equals [`VALUES_SHA256`].
    ///
    /// # Errors
    ///
    /// - [`TableError::Magic`]: not a table file.
    /// - [`TableError::Version`]: a table file of another layout version.
    /// - [`TableError::Length`]: truncated, or with bytes appended.
    /// - [`TableError::EntryCount`]: the header declares another number of
    ///   entries.
    /// - [`TableError::EntryNumber`]: an entry header carries another entry's
    ///   number.
    /// - [`TableError::Entry`]: an entry header declares another value count.
    /// - [`TableError::ValuesHash`]: the values are not the pinned ones.
    ///
    /// # Panics
    ///
    /// Does not panic.
    ///
    /// # Examples
    ///
    /// ```
    /// use g729::{FILE_LEN, TableError, Tables};
    ///
    /// assert_eq!(
    ///     Tables::from_bytes(b"not a table file").unwrap_err(),
    ///     TableError::Magic
    /// );
    /// assert_eq!(
    ///     Tables::from_bytes(b"G729TBL\0").unwrap_err(),
    ///     TableError::Length { expected: FILE_LEN, actual: 8 }
    /// );
    /// ```
    ///
    /// Loading the file written by [`import_from_itu`](crate::import_from_itu):
    ///
    /// ```no_run
    /// let tables = g729::Tables::from_bytes(&std::fs::read("g729-tables.bin")?)?;
    /// let decoder = g729::Decoder::new(&tables);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, TableError> {
        if bytes.len() < 12 {
            return Err(TableError::Length {
                expected: FILE_LEN,
                actual: bytes.len(),
            });
        }
        if &bytes[..8] != FILE_MAGIC {
            return Err(TableError::Magic);
        }
        let version = u16_at(bytes, 8);
        if version != FILE_VERSION {
            return Err(TableError::Version(version));
        }
        let count = usize::from(u16_at(bytes, 10));
        if count != ENTRIES.len() {
            return Err(TableError::EntryCount {
                expected: ENTRIES.len(),
                actual: count,
            });
        }
        let mut values = Vec::with_capacity(VALUE_COUNT);
        let mut at = 12;
        for (i, entry) in ENTRIES.iter().enumerate() {
            if bytes.len() < at + 6 {
                return Err(TableError::Length {
                    expected: FILE_LEN,
                    actual: bytes.len(),
                });
            }
            let index = usize::from(u16_at(bytes, at));
            let len = u32_at(bytes, at + 2) as usize;
            if index != i {
                return Err(TableError::EntryNumber {
                    position: i,
                    actual: index,
                });
            }
            if len != entry.len {
                return Err(TableError::Entry {
                    index: i,
                    expected: entry.len,
                    actual: len,
                });
            }
            at += 6;
            if bytes.len() < at + 2 * len {
                return Err(TableError::Length {
                    expected: FILE_LEN,
                    actual: bytes.len(),
                });
            }
            for k in 0..len {
                values.push(i16::from_le_bytes([
                    bytes[at + 2 * k],
                    bytes[at + 2 * k + 1],
                ]));
            }
            at += 2 * len;
        }
        if at != bytes.len() {
            return Err(TableError::Length {
                expected: FILE_LEN,
                actual: bytes.len(),
            });
        }
        if values_sha256(values.iter().copied()) != VALUES_SHA256 {
            return Err(TableError::ValuesHash);
        }
        Tables::from_values(&values).ok_or(TableError::Length {
            expected: FILE_LEN,
            actual: bytes.len(),
        })
    }

    /// sha256 of this value set, lowercase hex. Always [`VALUES_SHA256`],
    /// since only that value set loads.
    ///
    /// # Panics
    ///
    /// Does not panic.
    pub fn values_sha256_hex(&self) -> std::string::String {
        let mut values = Vec::with_capacity(VALUE_COUNT);
        self.for_each_value(|v| values.push(v));
        values_sha256(values)
    }
}
