// SPDX-License-Identifier: MIT OR Apache-2.0

//! A streaming, read-only tar reader.
//!
//! Enough of POSIX ustar, GNU and pax to walk the archives capture tools and
//! people actually produce, and nothing that writes to the filesystem. That
//! second half is the point: every well-known tar vulnerability lives in
//! *extraction* — a member named `../../etc/cron.d/x`, a symlink planted before
//! a file written through it, a hard link to a file outside the tree. This
//! reader never extracts. It hands the caller each entry's name as bytes and
//! its data as a bounded stream, and the caller decides where the data goes,
//! which in sipnab is always a file it named itself.
//!
//! # What is read
//!
//! - The 512-byte header, verified by its checksum before any field is
//!   believed. Both the unsigned and the historical signed sum are accepted,
//!   because old archivers wrote the signed one.
//! - `size` in octal, or in GNU base-256 for members over 8 GiB.
//! - The ustar `prefix`, which carries the leading part of a name longer than
//!   100 bytes in a POSIX archive.
//! - GNU long names (`L`) and pax extended headers (`x`), which override the
//!   next entry's name and, for pax, its size. Long link names (`K`) and pax
//!   global headers (`g`) are consumed and ignored.
//!
//! # What is not
//!
//! Data belongs only to regular files. POSIX says links, directories, device
//! nodes and fifos store no data blocks whatever their `size` field claims, and
//! this reader honors that rather than skipping `size` bytes that are not
//! there, which is how a lax reader loses its place. A GNU sparse member (`S`)
//! is reported as such, so the caller can refuse it: its `size` counts only the
//! stored fragments, and reading them as the file would splice a capture
//! together out of order.
//!
//! # Bounds
//!
//! The only memory this reader allocates in proportion to the input is the
//! text of a long name or a pax header, and that is capped at
//! [`MAX_META_BYTES`]. Member data is never buffered here; it streams to
//! whatever the caller copies it into.

use std::io::{self, Read};

/// Tar's block size. Headers occupy one block and data is padded to a
/// multiple of it.
pub const BLOCK: usize = 512;

/// Largest GNU long name or pax header this reader will hold in memory.
///
/// A path name is at most a few kilobytes on any real file system, and a pax
/// header carrying the handful of keys anyone writes is smaller still. A
/// header claiming more is not describing a file name.
pub const MAX_META_BYTES: u64 = 1024 * 1024;

/// What kind of file-system object an entry describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    /// A regular file (`0`, NUL, or the contiguous-file `7`), the only kind
    /// with data this reader hands out.
    File,
    /// A directory (`5`).
    Directory,
    /// A hard link to an earlier member (`1`).
    HardLink,
    /// A symbolic link (`2`).
    SymLink,
    /// A character device node (`3`).
    CharDevice,
    /// A block device node (`4`).
    BlockDevice,
    /// A fifo (`6`).
    Fifo,
    /// A GNU sparse file (`S`), whose stored data is not the file.
    Sparse,
    /// Any other type flag, carried so a refusal can name it.
    Other(u8),
}

/// One entry's header, after long-name and pax overrides are applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryHeader {
    /// The member's name exactly as the archive spells it. Never a path this
    /// reader or its caller opens.
    pub name: Vec<u8>,
    /// What the entry describes.
    pub kind: EntryKind,
    /// Bytes of data that follow the header. Zero for every kind that stores
    /// none, whatever the header's own `size` field said.
    pub size: u64,
    /// Offset of this entry's header block in the tar stream, for messages.
    pub offset: u64,
}

/// Why the walk could not go on.
#[derive(Debug)]
pub enum TarError {
    /// The underlying stream failed.
    Io(io::Error),
    /// A header's checksum does not match its bytes, so none of its fields
    /// can be believed — including the size that says where the next header
    /// is.
    BadChecksum {
        /// Offset of the header block.
        offset: u64,
    },
    /// A numeric field is not a number.
    BadNumber {
        /// Offset of the header block.
        offset: u64,
        /// Which field.
        field: &'static str,
    },
    /// A pax extended header is not a sequence of `LEN key=value\n` records.
    BadPax {
        /// Offset of the pax header block.
        offset: u64,
    },
    /// A long name or pax header larger than [`MAX_META_BYTES`].
    MetaTooLarge {
        /// Offset of the header block.
        offset: u64,
        /// The size it claimed.
        size: u64,
    },
    /// The stream ended inside a header or inside a long-name or pax block.
    Truncated {
        /// Offset at which the stream ran out.
        offset: u64,
    },
}

impl std::fmt::Display for TarError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "{e}"),
            Self::BadChecksum { offset } => write!(
                f,
                "the tar header at byte {offset} fails its checksum, so nothing after \
                 it can be located"
            ),
            Self::BadNumber { offset, field } => write!(
                f,
                "the tar header at byte {offset} has a {field} field that is not a number"
            ),
            Self::BadPax { offset } => {
                write!(f, "the pax extended header at byte {offset} is malformed")
            }
            Self::MetaTooLarge { offset, size } => write!(
                f,
                "the tar header at byte {offset} claims {size} bytes of name or \
                 extended-header text, more than the {MAX_META_BYTES} this reader holds"
            ),
            Self::Truncated { offset } => {
                write!(f, "the archive ends at byte {offset}, inside a header")
            }
        }
    }
}

impl std::error::Error for TarError {}

impl From<io::Error> for TarError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// Whether `block` is a tar header, judged the only way that means anything:
/// its checksum holds, and it either carries the ustar magic or a v7 type flag
/// and a name.
///
/// `false` for an all-zero block. That is the end-of-archive marker, not a
/// header, and a file that begins with one is not recognizably a tar.
#[must_use]
pub fn looks_like_header(block: &[u8]) -> bool {
    let Some(block) = block.get(..BLOCK) else {
        return false;
    };
    if block.iter().all(|&b| b == 0) || !checksum_holds(block) {
        return false;
    }
    let ustar = &block[257..262] == b"ustar";
    let v7 = matches!(block[156], b'0'..=b'7' | 0) && block[0] != 0;
    ustar || v7
}

/// Whether a header block's checksum field matches its bytes.
///
/// The field is summed as eight spaces. POSIX specifies an unsigned sum; some
/// historical writers produced a signed one, and both are accepted.
fn checksum_holds(block: &[u8]) -> bool {
    let Ok(stored) = parse_octal(&block[148..156]) else {
        return false;
    };
    let mut unsigned: u64 = 0;
    let mut signed: i64 = 0;
    for (i, &b) in block.iter().enumerate() {
        let b = if (148..156).contains(&i) { b' ' } else { b };
        unsigned += u64::from(b);
        signed += i64::from(b as i8);
    }
    stored == unsigned || i64::try_from(stored).is_ok_and(|s| s == signed)
}

/// Parse an octal numeric field: optional leading spaces, digits, then NUL or
/// space padding. An empty field is zero, as old writers left it.
fn parse_octal(field: &[u8]) -> Result<u64, ()> {
    let text = field
        .iter()
        .copied()
        .skip_while(|&b| b == b' ')
        .take_while(|&b| b != 0 && b != b' ');
    let mut value: u64 = 0;
    for b in text {
        if !(b'0'..=b'7').contains(&b) {
            return Err(());
        }
        value = value
            .checked_mul(8)
            .and_then(|v| v.checked_add(u64::from(b - b'0')))
            .ok_or(())?;
    }
    Ok(value)
}

/// Parse the `size` field: octal, or GNU base-256 when the high bit of the
/// first byte is set (sizes of 8 GiB and over).
fn parse_size(field: &[u8]) -> Result<u64, ()> {
    if field.first().is_some_and(|&b| b & 0x80 != 0) {
        // Big-endian two's complement over the whole field, first byte's high
        // bit excluded. A negative size, or one past u64, is not a size.
        let mut rest = field.iter().copied();
        let first = rest.next().unwrap_or(0) & 0x7f;
        if first & 0x40 != 0 {
            return Err(());
        }
        let mut value: u64 = u64::from(first);
        for b in rest {
            value = value
                .checked_mul(256)
                .and_then(|v| v.checked_add(u64::from(b)))
                .ok_or(())?;
        }
        return Ok(value);
    }
    parse_octal(field)
}

/// Bytes of zero padding that follow `size` bytes of data.
fn padding_for(size: u64) -> u64 {
    let block = BLOCK as u64;
    (block - size % block) % block
}

/// Trim a NUL-terminated header field to its text.
fn field_text(field: &[u8]) -> &[u8] {
    let end = field.iter().position(|&b| b == 0).unwrap_or(field.len());
    &field[..end]
}

/// The name a header spells on its own: the ustar prefix, when a POSIX
/// archive uses one, joined to the name field.
fn header_name(block: &[u8]) -> Vec<u8> {
    let name = field_text(&block[..100]);
    // POSIX ustar only: GNU archives ("ustar  ") reuse this region for other
    // fields, so reading it as a prefix there would invent directories.
    let posix = &block[257..263] == b"ustar\0";
    let prefix = if posix {
        field_text(&block[345..500])
    } else {
        &[]
    };
    if prefix.is_empty() {
        return name.to_vec();
    }
    let mut out = prefix.to_vec();
    out.push(b'/');
    out.extend_from_slice(name);
    out
}

/// The `path` and `size` keys of a pax extended header, the two that change
/// where a member's data is and what it is called.
fn parse_pax(data: &[u8]) -> Result<(Option<Vec<u8>>, Option<u64>), ()> {
    let mut path = None;
    let mut size = None;
    let mut rest = data;
    while !rest.is_empty() {
        // A block's worth of trailing NULs pads the last record; stop there.
        if rest.iter().all(|&b| b == 0) {
            break;
        }
        let space = rest.iter().position(|&b| b == b' ').ok_or(())?;
        let len: usize = std::str::from_utf8(&rest[..space])
            .map_err(|_| ())?
            .parse()
            .map_err(|_| ())?;
        if len <= space + 1 || len > rest.len() {
            return Err(());
        }
        let record = &rest[space + 1..len];
        let record = record.strip_suffix(b"\n").ok_or(())?;
        let eq = record.iter().position(|&b| b == b'=').ok_or(())?;
        let (key, value) = (&record[..eq], &record[eq + 1..]);
        match key {
            b"path" => path = Some(value.to_vec()),
            b"size" => {
                let text = std::str::from_utf8(value).map_err(|_| ())?;
                size = Some(text.parse().map_err(|_| ())?);
            }
            _ => {}
        }
        rest = &rest[len..];
    }
    Ok((path, size))
}

/// A tar stream being walked, one entry at a time.
pub struct TarReader<R> {
    /// The tar stream.
    inner: R,
    /// Bytes consumed from `inner`.
    pos: u64,
    /// Data bytes of the current entry not yet read by the caller.
    remaining: u64,
    /// Padding after the current entry's data.
    padding: u64,
    /// The end-of-archive marker, or a clean end of stream, has been seen.
    finished: bool,
}

impl<R: Read> TarReader<R> {
    /// Start walking `inner` from its first byte.
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            pos: 0,
            remaining: 0,
            padding: 0,
            finished: false,
        }
    }

    /// Advance to the next entry, skipping whatever of the current one the
    /// caller did not read.
    ///
    /// # Returns
    ///
    /// `Ok(None)` at the end-of-archive marker, and also at a clean end of
    /// stream on a block boundary: some writers omit the marker, and nothing
    /// is lost by accepting that.
    ///
    /// # Errors
    ///
    /// [`TarError`] for a header that fails its checksum, a malformed numeric
    /// field or pax record, an oversized long name, or a stream that ends
    /// inside a header.
    pub fn next_entry(&mut self) -> Result<Option<EntryHeader>, TarError> {
        if self.finished {
            return Ok(None);
        }
        // Whatever of the previous entry the caller left unread, and its
        // padding. Skipped by reading, because the stream may not seek.
        let skip = self.remaining + self.padding;
        self.remaining = 0;
        self.padding = 0;
        if skip > 0 {
            let skipped = io::copy(&mut (&mut self.inner).take(skip), &mut io::sink())?;
            self.pos += skipped;
            if skipped < skip {
                self.finished = true;
                return Err(TarError::Truncated { offset: self.pos });
            }
        }

        let mut long_name: Option<Vec<u8>> = None;
        let mut pax_path: Option<Vec<u8>> = None;
        let mut pax_size: Option<u64> = None;
        loop {
            let offset = self.pos;
            let mut block = [0u8; BLOCK];
            let got = self.fill(&mut block)?;
            if got == 0 {
                // A clean end on a block boundary: the writer omitted the
                // end-of-archive marker. Nothing is lost.
                self.finished = true;
                return Ok(None);
            }
            if got < BLOCK {
                self.finished = true;
                return Err(TarError::Truncated { offset: self.pos });
            }
            if block.iter().all(|&b| b == 0) {
                self.finished = true;
                return Ok(None);
            }
            if !checksum_holds(&block) {
                self.finished = true;
                return Err(TarError::BadChecksum { offset });
            }
            let header_size = parse_size(&block[124..136]).map_err(|()| {
                self.finished = true;
                TarError::BadNumber {
                    offset,
                    field: "size",
                }
            })?;
            let typeflag = block[156];
            match typeflag {
                b'L' | b'K' | b'x' | b'g' => {
                    let meta = self.read_meta(offset, header_size)?;
                    match typeflag {
                        b'L' => long_name = Some(field_text(&meta).to_vec()),
                        b'x' => {
                            let (p, sz) = parse_pax(&meta).map_err(|()| {
                                self.finished = true;
                                TarError::BadPax { offset }
                            })?;
                            if p.is_some() {
                                pax_path = p;
                            }
                            if sz.is_some() {
                                pax_size = sz;
                            }
                        }
                        // `K` names a link target and `g` sets defaults for
                        // the rest of the archive; neither changes where a
                        // member's data is or what it is called.
                        _ => {}
                    }
                    continue;
                }
                _ => {}
            }

            let kind = match typeflag {
                b'0' | 0 | b'7' => EntryKind::File,
                b'1' => EntryKind::HardLink,
                b'2' => EntryKind::SymLink,
                b'3' => EntryKind::CharDevice,
                b'4' => EntryKind::BlockDevice,
                b'5' => EntryKind::Directory,
                b'6' => EntryKind::Fifo,
                b'S' => EntryKind::Sparse,
                other => EntryKind::Other(other),
            };
            let declared = pax_size.unwrap_or(header_size);
            // POSIX stores no data blocks for these, whatever `size` says.
            let size = match kind {
                EntryKind::HardLink
                | EntryKind::SymLink
                | EntryKind::Directory
                | EntryKind::CharDevice
                | EntryKind::BlockDevice
                | EntryKind::Fifo => 0,
                _ => declared,
            };
            let name = long_name
                .or(pax_path)
                .unwrap_or_else(|| header_name(&block));
            self.remaining = size;
            self.padding = padding_for(size);
            return Ok(Some(EntryHeader {
                name,
                kind,
                size,
                offset,
            }));
        }
    }

    /// Read as much of one block as the stream holds, returning how much.
    fn fill(&mut self, block: &mut [u8; BLOCK]) -> Result<usize, TarError> {
        let mut got = 0;
        while got < BLOCK {
            match self.inner.read(&mut block[got..]) {
                Ok(0) => break,
                Ok(n) => got += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(TarError::Io(e)),
            }
        }
        self.pos += got as u64;
        Ok(got)
    }

    /// Read a long-name or pax header's data, bounded, and its padding.
    fn read_meta(&mut self, offset: u64, size: u64) -> Result<Vec<u8>, TarError> {
        if size > MAX_META_BYTES {
            self.finished = true;
            return Err(TarError::MetaTooLarge { offset, size });
        }
        let total = size + padding_for(size);
        let mut buf = Vec::new();
        let got = (&mut self.inner).take(total).read_to_end(&mut buf)?;
        self.pos += got as u64;
        if (got as u64) < total {
            self.finished = true;
            return Err(TarError::Truncated { offset: self.pos });
        }
        // Bounded by MAX_META_BYTES above, so the cast cannot truncate.
        buf.truncate(usize::try_from(size).unwrap_or(buf.len()));
        Ok(buf)
    }

    /// Bytes consumed from the underlying stream so far.
    #[must_use]
    pub fn position(&self) -> u64 {
        self.pos
    }

    /// A reader over the current entry's data, ending where the data does.
    ///
    /// A stream that ends before the entry does yields
    /// [`io::ErrorKind::UnexpectedEof`], so a truncated archive is reported
    /// rather than read as a short file.
    pub fn data(&mut self) -> EntryData<'_, R> {
        EntryData { tar: self }
    }
}

/// The data of one tar entry. See [`TarReader::data`].
pub struct EntryData<'a, R> {
    /// The reader whose current entry this is.
    tar: &'a mut TarReader<R>,
}

impl<R: Read> Read for EntryData<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.tar.remaining == 0 || buf.is_empty() {
            return Ok(0);
        }
        let want = usize::try_from(self.tar.remaining)
            .unwrap_or(usize::MAX)
            .min(buf.len());
        let n = self.tar.inner.read(&mut buf[..want])?;
        if n == 0 {
            // The stream ended inside this member. Report it: a member read
            // as shorter than its header says is a different file.
            self.tar.finished = true;
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!(
                    "the archive ends {} byte(s) short of this member's end",
                    self.tar.remaining
                ),
            ));
        }
        self.tar.remaining -= n as u64;
        self.tar.pos += n as u64;
        Ok(n)
    }
}

#[cfg(test)]
pub(crate) mod testutil {
    //! A minimal tar WRITER, for tests only.
    //!
    //! It shares no code with the reader above, so a misreading of the format
    //! in one does not silently agree with the other. The integration tests
    //! also read archives the system `tar` produced, which is the check this
    //! writer cannot give.

    /// One entry to write.
    pub struct Spec<'a> {
        /// Name as it goes in the header (and, when too long, in a GNU `L`).
        pub name: &'a [u8],
        /// Type flag byte.
        pub typeflag: u8,
        /// Data. Written only for the kinds that carry data.
        pub data: &'a [u8],
        /// The value to put in the `size` field, when it should differ from
        /// `data.len()` (links, directories).
        pub size_field: Option<u64>,
    }

    impl<'a> Spec<'a> {
        /// A regular file.
        pub fn file(name: &'a str, data: &'a [u8]) -> Self {
            Self {
                name: name.as_bytes(),
                typeflag: b'0',
                data,
                size_field: None,
            }
        }

        /// A directory.
        pub fn dir(name: &'a str) -> Self {
            Self {
                name: name.as_bytes(),
                typeflag: b'5',
                data: &[],
                size_field: None,
            }
        }
    }

    /// Build one ustar header block.
    pub fn header(name: &[u8], typeflag: u8, size: u64, ustar: bool) -> [u8; 512] {
        let mut h = [0u8; 512];
        let n = name.len().min(100);
        h[..n].copy_from_slice(&name[..n]);
        h[100..108].copy_from_slice(b"0000644\0");
        h[108..116].copy_from_slice(b"0000000\0");
        h[116..124].copy_from_slice(b"0000000\0");
        let size_text = format!("{size:011o}\0");
        h[124..136].copy_from_slice(size_text.as_bytes());
        h[136..148].copy_from_slice(b"14715254320\0");
        h[156] = typeflag;
        if ustar {
            h[257..263].copy_from_slice(b"ustar\0");
            h[263..265].copy_from_slice(b"00");
        }
        seal(&mut h);
        h
    }

    /// Write the checksum field over a header whose other fields are final.
    pub fn seal(h: &mut [u8; 512]) {
        h[148..156].copy_from_slice(b"        ");
        let sum: u32 = h.iter().map(|&b| u32::from(b)).sum();
        let text = format!("{sum:06o}\0 ");
        h[148..156].copy_from_slice(text.as_bytes());
    }

    fn pad(out: &mut Vec<u8>) {
        while !out.len().is_multiple_of(512) {
            out.push(0);
        }
    }

    /// Build a whole archive, end-of-archive marker included.
    pub fn build(entries: &[Spec<'_>]) -> Vec<u8> {
        let mut out = Vec::new();
        for e in entries {
            if e.name.len() > 100 {
                // GNU long name: the name as the data of an `L` entry.
                let mut long = e.name.to_vec();
                long.push(0);
                out.extend_from_slice(&header(b"././@LongLink", b'L', long.len() as u64, true));
                out.extend_from_slice(&long);
                pad(&mut out);
            }
            let size = e.size_field.unwrap_or(e.data.len() as u64);
            out.extend_from_slice(&header(e.name, e.typeflag, size, true));
            out.extend_from_slice(e.data);
            pad(&mut out);
        }
        out.extend_from_slice(&[0u8; 1024]);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::testutil::{Spec, build, header, seal};
    use super::*;

    /// Walk a whole archive, returning each entry and its data.
    fn walk(bytes: &[u8]) -> Result<Vec<(EntryHeader, Vec<u8>)>, TarError> {
        let mut tar = TarReader::new(bytes);
        let mut out = Vec::new();
        while let Some(h) = tar.next_entry()? {
            let mut data = Vec::new();
            tar.data().read_to_end(&mut data)?;
            out.push((h, data));
        }
        Ok(out)
    }

    #[test]
    fn regular_files_come_back_with_their_names_and_data() {
        let tar = build(&[
            Spec::file("a.pcap", b"first"),
            Spec::file("dir/b.pcap", &[7u8; 1300]),
        ]);
        let got = walk(&tar).expect("walk");
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].0.name, b"a.pcap");
        assert_eq!(got[0].0.kind, EntryKind::File);
        assert_eq!(got[0].1, b"first");
        assert_eq!(got[1].0.name, b"dir/b.pcap");
        assert_eq!(got[1].1, vec![7u8; 1300], "data spanning three blocks");
        assert_eq!(
            got[1].0.offset, 1024,
            "second header follows one data block"
        );
    }

    /// An entry the caller does not read is skipped whole, padding included,
    /// so the next header is found where it is.
    #[test]
    fn an_unread_entry_is_skipped_and_the_next_one_still_found() {
        let tar = build(&[
            Spec::file("skip.bin", &[1u8; 700]),
            Spec::file("keep", b"k"),
        ]);
        let mut r = TarReader::new(&tar[..]);
        let first = r.next_entry().expect("first").expect("some");
        assert_eq!(first.size, 700);
        let second = r.next_entry().expect("second").expect("some");
        assert_eq!(second.name, b"keep");
        let mut d = Vec::new();
        r.data().read_to_end(&mut d).expect("data");
        assert_eq!(d, b"k");
        assert!(r.next_entry().expect("end").is_none());
    }

    /// POSIX: links, directories, devices and fifos store no data, whatever
    /// the size field says. A reader that skipped `size` bytes for them would
    /// land in the middle of the next member.
    #[test]
    fn kinds_without_data_never_consume_the_next_member() {
        let tar = build(&[
            Spec {
                name: b"link",
                typeflag: b'1',
                data: &[],
                size_field: Some(4096),
            },
            Spec {
                name: b"sym",
                typeflag: b'2',
                data: &[],
                size_field: Some(4096),
            },
            Spec::dir("d/"),
            Spec {
                name: b"fifo",
                typeflag: b'6',
                data: &[],
                size_field: Some(512),
            },
            Spec::file("after", b"still here"),
        ]);
        let got = walk(&tar).expect("walk");
        let kinds: Vec<EntryKind> = got.iter().map(|(h, _)| h.kind).collect();
        assert_eq!(
            kinds,
            vec![
                EntryKind::HardLink,
                EntryKind::SymLink,
                EntryKind::Directory,
                EntryKind::Fifo,
                EntryKind::File
            ]
        );
        assert!(got[..4].iter().all(|(h, d)| h.size == 0 && d.is_empty()));
        assert_eq!(got[4].1, b"still here");
    }

    #[test]
    fn a_gnu_long_name_names_the_next_entry() {
        let long = format!("{}/capture.pcap", "d".repeat(150));
        let tar = build(&[Spec::file(&long, b"x")]);
        let got = walk(&tar).expect("walk");
        assert_eq!(got.len(), 1, "the L entry is metadata, not a member");
        assert_eq!(got[0].0.name, long.as_bytes());
    }

    #[test]
    fn a_pax_header_overrides_name_and_size() {
        let path = "pax/very-long-name.pcap";
        let record = |k: &str, v: &str| {
            // "LEN key=value\n", where LEN counts its own digits too.
            let body = format!(" {k}={v}\n");
            let mut len = body.len() + 1;
            while len != body.len() + len.to_string().len() {
                len = body.len() + len.to_string().len();
            }
            format!("{len}{body}")
        };
        let pax = format!("{}{}", record("path", path), record("size", "3"));
        let mut out = Vec::new();
        out.extend_from_slice(&header(b"PaxHeaders/x", b'x', pax.len() as u64, true));
        out.extend_from_slice(pax.as_bytes());
        while !out.len().is_multiple_of(512) {
            out.push(0);
        }
        // The ustar size field lies (0); pax says 3.
        out.extend_from_slice(&header(b"short", b'0', 0, true));
        out.extend_from_slice(b"abc");
        while !out.len().is_multiple_of(512) {
            out.push(0);
        }
        out.extend_from_slice(&[0u8; 1024]);
        let got = walk(&out).expect("walk");
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].0.name, path.as_bytes());
        assert_eq!(got[0].1, b"abc");
    }

    #[test]
    fn the_ustar_prefix_is_joined_to_the_name() {
        let mut h = header(b"file.pcap", b'0', 1, true);
        h[345..345 + 7].copy_from_slice(b"a/b/c/d");
        seal(&mut h);
        let mut out = h.to_vec();
        out.push(b'z');
        out.resize(1024, 0);
        out.extend_from_slice(&[0u8; 1024]);
        let got = walk(&out).expect("walk");
        assert_eq!(got[0].0.name, b"a/b/c/d/file.pcap");
    }

    /// A header whose checksum fails cannot be trusted to say where the next
    /// one is; the walk must stop, not guess.
    #[test]
    fn a_corrupt_header_stops_the_walk() {
        let mut tar = build(&[Spec::file("a", b"1"), Spec::file("b", b"2")]);
        tar[1024 + 10] ^= 0xff;
        let mut r = TarReader::new(&tar[..]);
        assert!(r.next_entry().expect("first ok").is_some());
        match r.next_entry() {
            Err(TarError::BadChecksum { offset }) => assert_eq!(offset, 1024),
            other => panic!("expected BadChecksum, got {other:?}"),
        }
    }

    /// Data cut short is an error the caller sees, not a short member.
    #[test]
    fn a_member_cut_short_reports_unexpected_eof() {
        let tar = build(&[Spec::file("big", &[9u8; 2000])]);
        let cut = &tar[..512 + 1000];
        let mut r = TarReader::new(cut);
        let h = r.next_entry().expect("header").expect("some");
        assert_eq!(h.size, 2000);
        let mut data = Vec::new();
        let err = r.data().read_to_end(&mut data).expect_err("truncated");
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
        assert_eq!(data.len(), 1000, "what WAS there is still delivered");
    }

    #[test]
    fn a_stream_ending_inside_a_header_is_truncated() {
        let tar = build(&[Spec::file("a", b"1")]);
        let cut = &tar[..1024 + 100];
        let mut r = TarReader::new(cut);
        assert!(r.next_entry().expect("first").is_some());
        assert!(matches!(r.next_entry(), Err(TarError::Truncated { .. })));
    }

    /// Some writers stop at the last member without the zero blocks.
    #[test]
    fn a_missing_end_marker_is_a_clean_end() {
        let tar = build(&[Spec::file("a", b"1")]);
        let got = walk(&tar[..1024]).expect("walk");
        assert_eq!(got.len(), 1);
    }

    #[test]
    fn a_huge_long_name_is_refused_not_buffered() {
        let mut out = header(b"././@LongLink", b'L', MAX_META_BYTES + 1, true).to_vec();
        out.extend_from_slice(&[b'a'; 512]);
        let mut r = TarReader::new(&out[..]);
        assert!(matches!(
            r.next_entry(),
            Err(TarError::MetaTooLarge { size, .. }) if size == MAX_META_BYTES + 1
        ));
    }

    #[test]
    fn base256_sizes_are_read() {
        let mut h = header(b"huge", b'0', 0, true);
        h[124..136].fill(0);
        h[124] = 0x80;
        // 9 GiB, past what eleven octal digits can say.
        let size: u64 = 9 << 30;
        h[128..136].copy_from_slice(&size.to_be_bytes());
        seal(&mut h);
        let mut r = TarReader::new(&h[..]);
        let e = r.next_entry().expect("header").expect("some");
        assert_eq!(e.size, size);
    }

    #[test]
    fn a_non_numeric_size_is_refused() {
        let mut h = header(b"bad", b'0', 0, true);
        h[124..136].copy_from_slice(b"12x45678901\0");
        seal(&mut h);
        let mut r = TarReader::new(&h[..]);
        assert!(matches!(
            r.next_entry(),
            Err(TarError::BadNumber { field: "size", .. })
        ));
    }

    #[test]
    fn a_sparse_member_is_named_as_sparse() {
        let tar = build(&[Spec {
            name: b"holes",
            typeflag: b'S',
            data: b"frag",
            size_field: None,
        }]);
        let got = walk(&tar).expect("walk");
        assert_eq!(got[0].0.kind, EntryKind::Sparse);
    }

    #[test]
    fn header_recognition() {
        let tar = build(&[Spec::file("a.pcap", b"x")]);
        assert!(looks_like_header(&tar[..512]), "a ustar header");
        assert!(
            !looks_like_header(&[0u8; 512]),
            "the end marker is not a header"
        );
        let mut bent = tar[..512].to_vec();
        bent[0] ^= 1;
        assert!(!looks_like_header(&bent), "a header whose checksum fails");
        assert!(!looks_like_header(&tar[..511]), "short of a block");
        // A v7 header: no magic, but a type flag and a name.
        let v7 = header(b"old.pcap", b'0', 1, false);
        assert!(looks_like_header(&v7));
    }

    /// The historical signed checksum, which some old writers produced, is
    /// accepted alongside the unsigned one POSIX specifies.
    #[test]
    fn a_signed_checksum_is_accepted() {
        let mut h = header("é.pcap".as_bytes(), b'0', 0, true);
        h[148..156].copy_from_slice(b"        ");
        let signed: i64 = h.iter().map(|&b| i64::from(b as i8)).sum();
        let text = format!("{signed:06o}\0 ");
        h[148..156].copy_from_slice(text.as_bytes());
        assert!(looks_like_header(&h));
    }
}
