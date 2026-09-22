// SPDX-License-Identifier: MIT OR Apache-2.0

//! Captures inside archives and compressed wrappers.
//!
//! People hand captures around wrapped: a `.pcap.gz`, a `.tgz` of a whole
//! capture session, a tar of `.pcap.gz` ring-buffer members. sipnab used to
//! gunzip one layer and hand libpcap whatever came out, so a `.tgz` reached
//! libpcap as a tar and failed with `unknown file format`, and the operator
//! had to unpack it by hand before sipnab would look at it.
//!
//! This module unwraps those layers and treats an archive the way
//! [`super::input_set`] treats a directory: every member that is a capture
//! joins the set, in first-packet order with everything else, and every
//! member that is not is named and counted with the reason.
//!
//! # One detection path
//!
//! Every layer is identified by its **first bytes**, never by its name —
//! [`sniff`] — for the reason `input_set` gives about `tg.pcap0`: names lie,
//! and the bytes are read anyway. The same walk handles a top-level
//! `.pcap.gz`, a `.tar`, a `.tgz`, and any nesting of those inside each other,
//! up to [`Limits::max_depth`] layers.
//!
//! # What never happens
//!
//! - **No path taken from an archive ever reaches the filesystem.** A member's
//!   data is written to a file this module names itself (`m00007.pcap`) inside
//!   a private directory it created. The member's name is only ever a label:
//!   it appears in output and in frame pointers, and a member called
//!   `../../etc/cron.d/x` produces a file called `m00003.pcap` like any other.
//!   Links, device nodes and fifos in an archive are never materialized.
//! - **No layer inflates without a bound.** Every byte any decompressor
//!   produces, summed across every layer of one input, counts against
//!   [`Limits::max_inflated_bytes`] — the same ceiling `--max-gunzip-bytes`
//!   has always set for a `.pcap.gz`. A nested bomb is refused at whichever
//!   layer first crosses it, having written no more than the ceiling.
//! - **No member disappears silently.** Each one is read, or is a
//!   [`Skipped`] with a [`SkipReason`], or lies past a [`Stop`] that says the
//!   walk ended and why.
//!
//! # Where the members live
//!
//! Extracted members are ordinary files in an [`ExtractDir`], so every reader
//! sipnab has — libpcap, the pcapng metadata reader that finds embedded TLS
//! secrets, the merged-pcapng reader, the `--cores` mapper — reads them exactly
//! as it reads a file on disk, and nothing downstream grew a second code path.
//! The directory is deleted when its owner drops it. A process that dies
//! without dropping it leaves it holding a lock that died with the process,
//! and the next extraction removes it (see [`ExtractDir`]).

#[cfg(feature = "archive")]
pub mod codepage;
#[cfg(feature = "archive")]
pub mod password;
pub mod tar;
#[cfg(all(feature = "archive", unix))]
pub mod tty;
#[cfg(feature = "archive")]
pub mod zipped;

use std::io::{self, Read};
use std::path::{Path, PathBuf};

/// What a byte stream is, judged by its first bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// A classic pcap capture, either byte order, micro- or nanosecond.
    Pcap,
    /// A pcapng capture.
    Pcapng,
    /// gzip, RFC 1952.
    Gzip,
    /// A tar archive: a checksum-valid header block.
    Tar,
    /// A ZIP archive.
    Zip,
    /// A 7-Zip archive.
    SevenZip,
    /// Zstandard.
    Zstd,
    /// xz.
    Xz,
    /// bzip2.
    Bzip2,
    /// LZ4 frame format.
    Lz4,
    /// Zero bytes.
    Empty,
    /// None of the above.
    Unknown,
}

impl Format {
    /// The name an operator knows this format by.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Pcap => "pcap",
            Self::Pcapng => "pcapng",
            Self::Gzip => "gzip",
            Self::Tar => "tar",
            Self::Zip => "ZIP",
            Self::SevenZip => "7-Zip",
            Self::Zstd => "Zstandard",
            Self::Xz => "xz",
            Self::Bzip2 => "bzip2",
            Self::Lz4 => "LZ4",
            Self::Empty => "empty",
            Self::Unknown => "unknown",
        }
    }
}

/// Identify a stream from its first bytes. Pass at least 512 when the stream
/// has them: a tar header is a whole block, and fewer bytes can never be one.
#[must_use]
pub fn sniff(head: &[u8]) -> Format {
    const PCAP: [[u8; 4]; 4] = [
        [0xd4, 0xc3, 0xb2, 0xa1],
        [0xa1, 0xb2, 0xc3, 0xd4],
        [0x4d, 0x3c, 0xb2, 0xa1],
        [0xa1, 0xb2, 0x3c, 0x4d],
    ];
    if head.is_empty() {
        return Format::Empty;
    }
    if head.len() >= 4 && PCAP.iter().any(|m| head[..4] == m[..]) {
        return Format::Pcap;
    }
    if head.starts_with(&[0x0a, 0x0d, 0x0d, 0x0a]) {
        return Format::Pcapng;
    }
    if head.starts_with(&[0x1f, 0x8b]) {
        return Format::Gzip;
    }
    if head.starts_with(b"PK\x03\x04") || head.starts_with(b"PK\x05\x06") {
        return Format::Zip;
    }
    if head.starts_with(&[b'7', b'z', 0xbc, 0xaf, 0x27, 0x1c]) {
        return Format::SevenZip;
    }
    if head.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
        return Format::Zstd;
    }
    if head.starts_with(&[0xfd, b'7', b'z', b'X', b'Z', 0x00]) {
        return Format::Xz;
    }
    // "BZh" and a block-size digit: three letters alone are too common in
    // text to mean bzip2.
    if head.len() >= 4 && head.starts_with(b"BZh") && (b'1'..=b'9').contains(&head[3]) {
        return Format::Bzip2;
    }
    if head.starts_with(&[0x04, 0x22, 0x4d, 0x18]) {
        return Format::Lz4;
    }
    if tar::looks_like_header(head) {
        return Format::Tar;
    }
    Format::Unknown
}

/// [`read_head`], keeping what arrived when the stream breaks part way: the
/// byte count, and the error that ended the read, if one did.
fn read_head_partial(src: &mut dyn Read, buf: &mut [u8]) -> (usize, Option<io::Error>) {
    let mut got = 0;
    while got < buf.len() {
        match src.read(&mut buf[got..]) {
            Ok(0) => break,
            Ok(n) => got += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return (got, Some(e)),
        }
    }
    (got, None)
}

/// Read into `buf` until it is full or the stream ends, returning how much.
fn read_head(src: &mut dyn Read, buf: &mut [u8]) -> io::Result<usize> {
    let mut got = 0;
    while got < buf.len() {
        match src.read(&mut buf[got..]) {
            Ok(0) => break,
            Ok(n) => got += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(got)
}

/// One wrapper unwrapped on the way to a capture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layer {
    /// A gzip stream.
    Gzip,
    /// A tar archive.
    Tar,
    /// A ZIP archive.
    Zip,
}

impl Layer {
    /// Short name for reports.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Gzip => "gzip",
            Self::Tar => "tar",
            Self::Zip => "zip",
        }
    }
}

/// How an archive member is encrypted, as the summary reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Encryption {
    /// Not encrypted.
    #[default]
    None,
    /// PKWARE's traditional ZIP encryption, which protects nothing: twelve
    /// known bytes recover its keys.
    ZipCrypto,
    /// WinZip AES with a 128-bit key.
    Aes128,
    /// WinZip AES with a 192-bit key.
    Aes192,
    /// WinZip AES with a 256-bit key.
    Aes256,
}

impl Encryption {
    /// The name the summary uses: `none`, `zipcrypto`, `aes-128`, `aes-192`
    /// or `aes-256`.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::ZipCrypto => "zipcrypto",
            Self::Aes128 => "aes-128",
            Self::Aes192 => "aes-192",
            Self::Aes256 => "aes-256",
        }
    }
}

/// How far one input may be unwrapped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Bytes every decompressor of one input may produce, summed across
    /// layers. The shipped value is `--max-gunzip-bytes`.
    pub max_inflated_bytes: u64,
    /// Archive entries — members, directories and links alike — one input may
    /// hold before the walk stops.
    pub max_entries: usize,
    /// Wrappers that may be nested: `capture.pcap.gz` is one, a `.tgz` is two,
    /// a `.pcap.gz` inside a `.tgz` is three.
    pub max_depth: usize,
}

/// Archive entries one input may hold. A capture set of a few hundred ring
/// files is ordinary; ten thousand entries is a directory tree, not captures,
/// and each entry costs a header read even when it is skipped.
pub const MAX_ENTRIES: usize = 10_000;

/// Wrappers one input may nest. Three covers the deepest real shape — a
/// `.pcap.gz` member of a `.tgz` — with one to spare; past that the nesting is
/// the construction of a decompression bomb rather than a way to ship files.
pub const MAX_DEPTH: usize = 4;

impl Limits {
    /// The limits a run uses: the process's `--max-gunzip-bytes` ceiling and
    /// the shipped entry and depth caps.
    #[must_use]
    pub fn for_run() -> Self {
        Self {
            max_inflated_bytes: super::pcap_reader::max_gunzip_bytes(),
            max_entries: MAX_ENTRIES,
            max_depth: MAX_DEPTH,
        }
    }
}

/// One capture found inside an input and written out to be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    /// The name this capture goes by in output and in frame pointers:
    /// `<archive path>/<member name>`, nested as deep as the archive is.
    pub label: String,
    /// Where its bytes were written: a file this module named, inside the
    /// [`ExtractDir`].
    pub path: PathBuf,
    /// The wrappers unwrapped to reach it, outermost first.
    pub layers: Vec<Layer>,
    /// Why this member ends before its archive said it would, when it does:
    /// the archive was cut short, or a gzip layer broke off. What arrived is
    /// still written and read, the way a truncated capture file is.
    pub cut_short: Option<String>,
    /// How the archive member it came out of was encrypted.
    pub encryption: Encryption,
}

/// Why a member was not read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SkipReason {
    /// The member holds no bytes at all.
    Empty,
    /// The member is not a pcap, a pcapng, or a wrapper around one. Carries
    /// its first bytes, which is what identifies what it IS.
    NotACapture {
        /// Up to its first four bytes, in hex.
        head: String,
    },
    /// A format sipnab recognizes and cannot open.
    Unsupported(Format),
    /// A hard or symbolic link. Never followed: a link's target is a path, and
    /// no path from an archive reaches the filesystem.
    Link,
    /// A device node or fifo, which holds no data.
    Special,
    /// A GNU sparse member, whose stored bytes are not the file.
    Sparse,
    /// A tar type flag this reader does not know.
    OtherType(u8),
    /// A second member with a name an earlier one already has. The first is
    /// read; a pointer naming this label could not say which of the two it
    /// meant.
    DuplicateName,
    /// Nested more deeply than [`Limits::max_depth`].
    TooDeep,
    /// Encrypted, and no password was available to try.
    EncryptedNoPassword,
    /// Encrypted, and every password tried was wrong.
    EncryptedWrongPassword,
    /// Encrypted in a way sipnab cannot decrypt whatever the password.
    EncryptionUnsupported(String),
    /// A ZIP member compressed with a method sipnab does not inflate.
    ZipMethod(u16),
}

impl std::fmt::Display for SkipReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "empty (0 bytes)"),
            Self::NotACapture { head } => {
                write!(
                    f,
                    "not a capture (starts with {head}, which is not pcap or pcapng)"
                )
            }
            Self::Unsupported(fmt) => write!(
                f,
                "{} data, which sipnab does not unwrap; unpack it and point -I at what comes out",
                fmt.name()
            ),
            Self::Link => write!(f, "a link, which is never followed"),
            Self::Special => write!(f, "a device node or fifo, which holds no data"),
            Self::Sparse => write!(f, "a sparse member, whose stored bytes are not the file"),
            Self::OtherType(t) => write!(
                f,
                "an entry of tar type {:?}, which is not a file",
                *t as char
            ),
            Self::DuplicateName => write!(
                f,
                "a second member with the same name; the first was read, and a frame \
                 pointer could not tell the two apart"
            ),
            Self::TooDeep => write!(
                f,
                "nested more than {MAX_DEPTH} wrappers deep, which is how a decompression \
                 bomb is built rather than how captures are shipped"
            ),
            Self::EncryptedNoPassword => write!(
                f,
                "encrypted, and no password was supplied (--archive-password-file, \
                 --archive-password-command, --archive-password-stdin, or the prompt)"
            ),
            Self::EncryptedWrongPassword => {
                write!(f, "encrypted, and no password supplied opens it")
            }
            Self::EncryptionUnsupported(why) => {
                write!(f, "encrypted in a way sipnab cannot decrypt ({why})")
            }
            Self::ZipMethod(m) => write!(
                f,
                "compressed with ZIP method {m}, which sipnab does not inflate; unpack it \
                 and point -I at what comes out"
            ),
        }
    }
}

impl SkipReason {
    /// A stable short key, for counting skips by reason.
    #[must_use]
    pub fn key(&self) -> &'static str {
        match self {
            Self::Empty => "empty",
            Self::NotACapture { .. } => "not a capture",
            Self::Unsupported(_) => "unsupported format",
            Self::Link => "link",
            Self::Special => "special file",
            Self::Sparse => "sparse",
            Self::OtherType(_) => "unknown entry type",
            Self::DuplicateName => "duplicate name",
            Self::TooDeep => "nested too deep",
            Self::EncryptedNoPassword => "encrypted, no password",
            Self::EncryptedWrongPassword => "encrypted, wrong password",
            Self::EncryptionUnsupported(_) => "encryption unsupported",
            Self::ZipMethod(_) => "unsupported compression",
        }
    }

    /// The reason in the vocabulary every surface's summary shares:
    /// `encrypted_no_password`, `not_a_capture`, `nested_too_deep` and so on.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Empty => "empty",
            Self::NotACapture { .. } => "not_a_capture",
            Self::Unsupported(_) => "unsupported_format",
            Self::Link => "link",
            Self::Special => "special_file",
            Self::Sparse => "sparse",
            Self::OtherType(_) => "unknown_entry_type",
            Self::DuplicateName => "duplicate_name",
            Self::TooDeep => "nested_too_deep",
            Self::EncryptedNoPassword => "encrypted_no_password",
            Self::EncryptedWrongPassword => "encrypted_wrong_password",
            Self::EncryptionUnsupported(_) => "encryption_unsupported",
            Self::ZipMethod(_) => "unsupported_compression",
        }
    }

    /// Whether the member was skipped for want of the right password.
    #[must_use]
    pub fn is_locked(&self) -> bool {
        matches!(
            self,
            Self::EncryptedNoPassword | Self::EncryptedWrongPassword
        )
    }
}

/// A member that was not read, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skipped {
    /// The member's label, as a [`Member`] would have had.
    pub label: String,
    /// Why it was not read.
    pub reason: SkipReason,
    /// How the member was encrypted.
    pub encryption: Encryption,
}

/// Why the walk ended before the archive did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stop {
    /// The decompressors produced [`Limits::max_inflated_bytes`] and more was
    /// coming. `at` is the member being written when the ceiling was reached;
    /// it was discarded, not kept in part.
    InflationCap {
        /// The ceiling.
        limit: u64,
        /// Label of the member being written, or of the container, when the
        /// ceiling was reached.
        at: String,
    },
    /// The archive held more than [`Limits::max_entries`] entries.
    EntryCap {
        /// The ceiling.
        limit: usize,
    },
    /// A container could not be walked further: a header failed its checksum,
    /// a gzip stream broke, or the archive ended inside a header.
    Broken {
        /// Label of the container that broke.
        container: String,
        /// What was wrong.
        detail: String,
    },
    /// Writing an extracted member failed — most often a full disk.
    WriteFailed {
        /// Label of the member.
        at: String,
        /// The error.
        detail: String,
    },
}

impl std::fmt::Display for Stop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InflationCap { limit, at } => write!(
                f,
                "decompressing reached the {limit}-byte ceiling at '{at}', so it and \
                 everything after it were not read; raise --max-gunzip-bytes (or \
                 [limits] max_gunzip_bytes) for an archive you trust"
            ),
            Self::EntryCap { limit } => write!(
                f,
                "the archive holds more than {limit} entries; the rest were not read"
            ),
            Self::Broken { container, detail } => {
                write!(
                    f,
                    "'{container}' could not be read past this point: {detail}"
                )
            }
            Self::WriteFailed { at, detail } => {
                write!(f, "could not write '{at}' out to read it: {detail}")
            }
        }
    }
}

/// Everything one input unwrapped to.
#[derive(Debug, Default)]
pub struct Expansion {
    /// Captures written out to be read, in archive order.
    pub members: Vec<Member>,
    /// Members not read, in archive order.
    pub skipped: Vec<Skipped>,
    /// Directory entries passed over. Counted, never reported as skipped: a
    /// directory in an archive is structure, not a capture that went missing.
    pub directories: usize,
    /// Members a name filter declined, which is what the operator asked for.
    pub filtered: usize,
    /// Why the walk ended early, when it did. Every member after this point
    /// is unaccounted for, which is why it is carried at all.
    pub stops: Vec<Stop>,
    /// The directory holding [`Self::members`]' files. Dropping the expansion
    /// deletes it.
    dir: Option<ExtractDir>,
}

impl Expansion {
    /// Whether capture data was lost rather than declined: the walk stopped
    /// early, or a member broke off before its end. A skipped member is
    /// accounted for by its reason and does not make an expansion lossy.
    #[must_use]
    pub fn lossy(&self) -> bool {
        !self.stops.is_empty() || self.members.iter().any(|m| m.cut_short.is_some())
    }

    /// Move the extraction directory out, so it can outlive this value.
    pub fn take_dir(&mut self) -> Option<ExtractDir> {
        self.dir.take()
    }
}

/// Whether this build unwraps `format` rather than handing it to libpcap or
/// naming it unsupported: gzip and tar always, ZIP with the `archive`
/// feature.
#[must_use]
pub fn unwraps(format: Format) -> bool {
    matches!(format, Format::Gzip | Format::Tar)
        || (format == Format::Zip && cfg!(feature = "archive"))
}

/// Whether `path` is a wrapper this module unwraps, and which.
///
/// `Ok(None)` for a capture, for an empty file, and for anything unrecognized
/// — those are libpcap's to accept or refuse, exactly as before this module
/// existed.
///
/// # Errors
///
/// When the file cannot be opened or read.
pub fn container_format(path: &Path) -> io::Result<Option<Format>> {
    let mut head = [0u8; tar::BLOCK];
    let mut file = std::fs::File::open(path)?;
    let n = read_head(&mut file, &mut head)?;
    Ok(match sniff(&head[..n]) {
        f @ (Format::Gzip
        | Format::Tar
        | Format::Zip
        | Format::SevenZip
        | Format::Zstd
        | Format::Xz
        | Format::Bzip2
        | Format::Lz4) => Some(f),
        Format::Pcap | Format::Pcapng | Format::Empty | Format::Unknown => None,
    })
}

/// Whether a file NAME looks like something sipnab reads: a pcap, pcapng or
/// `.cap`, optionally gzip-compressed, or a tar archive (`.tar`, `.tgz`,
/// `.tar.gz`). Case-insensitive.
///
/// For listings only — the TUI's file browser and MCP `list_captures` —
/// where opening every file in a directory to sniff it would be the wrong
/// cost. Reading a file never consults this: [`sniff`] decides that.
#[must_use]
pub fn is_capture_file_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    if lower.ends_with(".tar") || lower.ends_with(".tgz") || lower.ends_with(".tar.gz") {
        // A bare ".tar" is a dotfile, not an archive of anything.
        return !matches!(lower.as_str(), ".tar" | ".tgz" | ".tar.gz");
    }
    if cfg!(feature = "archive") && lower.ends_with(".zip") {
        return lower != ".zip";
    }
    // Peel an optional `.gz` so `foo.pcap.gz` is judged by its `.pcap` stem.
    let stem = lower.strip_suffix(".gz").unwrap_or(lower.as_str());
    Path::new(stem)
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| matches!(e, "pcap" | "pcapng" | "cap"))
}

/// Whether `path` holds several members to choose between — a tar, possibly
/// gzip-compressed — rather than being one capture, compressed or not.
///
/// Decides whether `--input-name` applies to a file named directly: it filters
/// what is found inside a container, and a `.pcap.gz` contains no choice.
#[must_use]
pub fn holds_members(path: &Path) -> bool {
    let Ok(file) = std::fs::File::open(path) else {
        return false;
    };
    let mut src = io::BufReader::new(file);
    let mut head = [0u8; tar::BLOCK];
    let Ok(n) = read_head(&mut src, &mut head) else {
        return false;
    };
    match sniff(&head[..n]) {
        Format::Tar => true,
        Format::Zip => unwraps(Format::Zip),
        Format::Gzip => {
            let mut dec = flate2::read::MultiGzDecoder::new((&head[..n]).chain(src));
            let mut inner = [0u8; tar::BLOCK];
            read_head(&mut dec, &mut inner)
                .map(|m| sniff(&inner[..m]) == Format::Tar)
                .unwrap_or(false)
        }
        _ => false,
    }
}

/// Unwrap every layer of `path` and write out the captures inside.
///
/// # Errors
///
/// Only when `path` itself cannot be opened, or the extraction directory
/// cannot be created. Everything that goes wrong INSIDE the input is carried
/// in the returned [`Expansion`] — a skipped member or a [`Stop`] — because a
/// broken archive still holds whatever was read before the break.
pub fn expand(path: &Path, limits: &Limits) -> io::Result<Expansion> {
    expand_filtered(path, limits, None)
}

/// [`expand`], writing out only the archive members whose file name `keep`
/// accepts. The rest are counted in [`Expansion::filtered`] and never written.
///
/// A member's file name is the last component of its name inside the archive,
/// which is what `--input-name` matches in a directory as well.
///
/// # Errors
///
/// As [`expand`].
pub fn expand_filtered(
    path: &Path,
    limits: &Limits,
    keep: Option<&dyn Fn(&str) -> bool>,
) -> io::Result<Expansion> {
    #[cfg(feature = "archive")]
    {
        password::with_run_keyring(|keyring| expand_filtered_with(path, limits, keep, keyring))
    }
    #[cfg(not(feature = "archive"))]
    {
        expand_filtered_inner(path, limits, keep)
    }
}

/// [`expand_filtered`] with an explicit keyring for encrypted members,
/// instead of the run's: a REST request that brought its own password, or a
/// test.
///
/// # Errors
///
/// As [`expand`].
#[cfg(feature = "archive")]
pub fn expand_filtered_with(
    path: &Path,
    limits: &Limits,
    keep: Option<&dyn Fn(&str) -> bool>,
    keyring: Option<&mut password::Keyring>,
) -> io::Result<Expansion> {
    let mut file = io::BufReader::new(std::fs::File::open(path)?);
    let label = path.display().to_string();
    let mut walker = Walker::new(limits, None, path, &label);
    walker.keep = keep;
    walker.keyring = keyring;
    // The outcome is recorded inside the walker; `Abort` only means the walk
    // could not go on, and the expansion says why.
    let _ = walker.walk(&mut file, &label, &[], 0);
    if let Some(e) = walker.fatal.take() {
        return Err(e);
    }
    Ok(walker.out)
}

/// [`expand_filtered`] in a build without encrypted-archive support.
#[cfg(not(feature = "archive"))]
fn expand_filtered_inner(
    path: &Path,
    limits: &Limits,
    keep: Option<&dyn Fn(&str) -> bool>,
) -> io::Result<Expansion> {
    let mut file = io::BufReader::new(std::fs::File::open(path)?);
    let label = path.display().to_string();
    let mut walker = Walker::new(limits, None, path, &label);
    walker.keep = keep;
    let _ = walker.walk(&mut file, &label, &[], 0);
    if let Some(e) = walker.fatal.take() {
        return Err(e);
    }
    Ok(walker.out)
}

/// Write out the one member of `path` whose label is `label`, for following a
/// frame pointer back to its bytes.
///
/// Walks the same layers [`expand`] does, and applies the same label rules,
/// so a label an expansion produced finds the same member here — including
/// through nested archives and gzip members.
///
/// # Returns
///
/// `Ok(None)` when no member has that label.
///
/// # Errors
///
/// When `path` cannot be read, or the walk stops before reaching the member.
pub fn extract_member(
    path: &Path,
    label: &str,
    limits: &Limits,
) -> io::Result<Option<(Member, ExtractDir)>> {
    #[cfg(feature = "archive")]
    {
        password::with_run_keyring(|keyring| extract_member_with(path, label, limits, keyring))
    }
    #[cfg(not(feature = "archive"))]
    {
        extract_member_inner(path, label, limits, ())
    }
}

/// [`extract_member`] with an explicit keyring for encrypted members.
///
/// # Errors
///
/// As [`extract_member`].
#[cfg(feature = "archive")]
pub fn extract_member_with(
    path: &Path,
    label: &str,
    limits: &Limits,
    keyring: Option<&mut password::Keyring>,
) -> io::Result<Option<(Member, ExtractDir)>> {
    extract_member_inner(path, label, limits, keyring)
}

/// The keyring a walk is handed: a real one where encrypted archives are
/// supported, nothing where they are not.
#[cfg(feature = "archive")]
type KeyringArg<'k> = Option<&'k mut password::Keyring>;
/// The keyring a walk is handed: a real one where encrypted archives are
/// supported, nothing where they are not.
#[cfg(not(feature = "archive"))]
type KeyringArg<'k> = ();

/// [`extract_member`], with the keyring given.
fn extract_member_inner(
    path: &Path,
    label: &str,
    limits: &Limits,
    keyring: KeyringArg<'_>,
) -> io::Result<Option<(Member, ExtractDir)>> {
    let mut file = io::BufReader::new(std::fs::File::open(path)?);
    let root = path.display().to_string();
    let mut walker = Walker::new(limits, Some(label), path, &root);
    #[cfg(feature = "archive")]
    {
        walker.keyring = keyring;
    }
    #[cfg(not(feature = "archive"))]
    let () = keyring;
    let _ = walker.walk(&mut file, &root, &[], 0);
    if let Some(e) = walker.fatal.take() {
        return Err(e);
    }
    let mut out = walker.out;
    if let Some(member) = out.members.pop() {
        return match out.dir.take() {
            Some(dir) => Ok(Some((member, dir))),
            None => Err(io::Error::other("extracted member has no directory")),
        };
    }
    // Not found. A walk that stopped early has not shown the member is
    // absent, so say what stopped it instead of "no such member".
    if let Some(stop) = out.stops.first() {
        return Err(io::Error::other(stop.to_string()));
    }
    Ok(None)
}

/// The archive a member label points into, when `source` is one.
///
/// A label is `<archive path>/<member name>`: a path whose leading part is a
/// regular FILE. No real path continues past a file, so the first existing
/// ancestor of `source` decides — a wrapper this module unwraps means `source`
/// is a member label, and anything else (a directory, a capture, nothing at
/// all) means it is not.
///
/// Only ever asked about a `source` that does not itself exist; a label never
/// shadows a real file.
#[must_use]
pub fn locate_member(source: &str) -> Option<PathBuf> {
    for ancestor in Path::new(source).ancestors().skip(1) {
        if ancestor.as_os_str().is_empty() {
            return None;
        }
        let Ok(meta) = std::fs::metadata(ancestor) else {
            continue;
        };
        if !meta.is_file() {
            return None;
        }
        return match container_format(ancestor) {
            Ok(Some(f)) if unwraps(f) => Some(ancestor.to_path_buf()),
            _ => None,
        };
    }
    None
}

/// Marker carried inside an [`io::Error`] when the inflation ceiling is hit,
/// so the walk can tell "the budget ran out" from "the stream broke" through
/// any number of reader layers.
#[derive(Debug)]
struct CeilingReached;

impl std::fmt::Display for CeilingReached {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "decompression ceiling reached")
    }
}

impl std::error::Error for CeilingReached {}

/// The part of a label a tar member contributes: its name as text, with the
/// spelling variants that name the same member folded together.
///
/// Leading `/` and `./`, empty components and `.` components go, so
/// `./set/a.pcap`, `/set/a.pcap` and `set//a.pcap` label one member alike.
/// `..` is KEPT: a label is never a path, so it cannot climb anywhere, and
/// dropping it would give two different members one label. Control
/// characters are escaped, because a label is printed.
#[must_use]
pub fn member_name(raw: &[u8]) -> String {
    let text = String::from_utf8_lossy(raw);
    let joined = text
        .split('/')
        .filter(|c| !c.is_empty() && *c != ".")
        .collect::<Vec<_>>()
        .join("/");
    let mut out = String::with_capacity(joined.len());
    for ch in joined.chars() {
        if ch.is_control() {
            out.extend(ch.escape_default());
        } else {
            out.push(ch);
        }
    }
    if out.is_empty() {
        out.push_str("(unnamed)");
    }
    out
}

/// Whether `e` is the inflation ceiling, however deeply it was wrapped.
fn is_ceiling(e: &io::Error) -> bool {
    e.get_ref()
        .is_some_and(|inner| inner.downcast_ref::<CeilingReached>().is_some())
}

/// A decompressor's output, counted against one input's inflation budget.
///
/// Every layer of one input shares the same counter, so a gzip inside a tar
/// inside a gzip is bounded by the SUM of what all three produce.
struct Inflating<R> {
    /// The decompressor.
    inner: R,
    /// Bytes every decompressor of this input has produced so far.
    used: std::rc::Rc<std::cell::Cell<u64>>,
    /// The ceiling.
    limit: u64,
}

impl<R: Read> Read for Inflating<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let used = self.used.get();
        if used >= self.limit {
            // One probe byte past the ceiling decides whether there is more:
            // a stream that ends exactly at the ceiling is within it.
            let mut probe = [0u8; 1];
            return match self.inner.read(&mut probe)? {
                0 => Ok(0),
                _ => Err(io::Error::other(CeilingReached)),
            };
        }
        let room = usize::try_from(self.limit - used).unwrap_or(usize::MAX);
        let want = buf.len().min(room);
        let n = self.inner.read(&mut buf[..want])?;
        self.used.set(used + n as u64);
        Ok(n)
    }
}

/// Whether the walk goes on after a node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Flow {
    /// Carry on with the next entry.
    Continue,
    /// The underlying stream can no longer be trusted; stop everything.
    Abort,
}

/// The state of one input's walk.
struct Walker<'l> {
    /// The limits in force.
    limits: &'l Limits,
    /// Inflated bytes so far, shared with every [`Inflating`] layer.
    used: std::rc::Rc<std::cell::Cell<u64>>,
    /// Archive entries seen so far, of every kind.
    entries: usize,
    /// Member labels already seen, for [`SkipReason::DuplicateName`].
    seen: std::collections::HashSet<String>,
    /// The one label to materialize, when following a pointer.
    wanted: Option<&'l str>,
    /// Which archive members to write out, by file name, when filtering.
    keep: Option<&'l dyn Fn(&str) -> bool>,
    /// What the walk found.
    out: Expansion,
    /// A failure that is not about the input: the extraction directory could
    /// not be made.
    fatal: Option<io::Error>,
    /// The file the walk started from, which a ZIP at the top can be read
    /// from directly instead of being copied.
    #[cfg_attr(not(feature = "archive"), allow(dead_code))]
    root: Option<&'l Path>,
    /// The label of [`Self::root`].
    #[cfg_attr(not(feature = "archive"), allow(dead_code))]
    root_label: &'l str,
    /// Passwords for encrypted members, when any are available.
    #[cfg(feature = "archive")]
    keyring: Option<&'l mut password::Keyring>,
    /// Nested archives copied out so far, for naming the copies.
    #[cfg(feature = "archive")]
    spills: usize,
    /// How the member being walked is encrypted, stamped on what comes out.
    encryption: Encryption,
    /// Reading a member with a password that has not yet proven itself: a
    /// stream that breaks, or data that is no capture and fails its check,
    /// means the password was wrong rather than that the member is damaged.
    trial: bool,
    /// Set during a trial when what came out shows the password was wrong.
    rejected: bool,
    /// Labels claimed in [`Self::seen`], in order, so a trial can give back
    /// the ones it claimed.
    seen_log: Vec<String>,
    /// Member files written so far, rolled-back ones included, so no name is
    /// ever reused within one extraction directory.
    members_written: usize,
}

/// Where a walk's records stood before a trial, so a failed one can be
/// undone.
#[derive(Debug, Clone, Copy)]
struct Checkpoint {
    /// `out.members.len()`.
    members: usize,
    /// `out.skipped.len()`.
    skipped: usize,
    /// `out.stops.len()`.
    stops: usize,
    /// `out.directories`.
    directories: usize,
    /// `out.filtered`.
    filtered: usize,
    /// `seen_log.len()`.
    seen: usize,
}

impl<'l> Walker<'l> {
    /// A walk under `limits` of the file `root` labeled `root_label`,
    /// materializing only `wanted` when it is set.
    fn new(
        limits: &'l Limits,
        wanted: Option<&'l str>,
        root: &'l Path,
        root_label: &'l str,
    ) -> Self {
        Self {
            limits,
            used: std::rc::Rc::new(std::cell::Cell::new(0)),
            entries: 0,
            seen: std::collections::HashSet::new(),
            wanted,
            keep: None,
            out: Expansion::default(),
            fatal: None,
            root: Some(root),
            root_label,
            #[cfg(feature = "archive")]
            keyring: None,
            #[cfg(feature = "archive")]
            spills: 0,
            encryption: Encryption::None,
            trial: false,
            rejected: false,
            seen_log: Vec::new(),
            members_written: 0,
        }
    }

    /// Claim `label` as seen; `false` when an earlier member has it.
    fn claim(&mut self, label: &str) -> bool {
        if !self.seen.insert(label.to_string()) {
            return false;
        }
        self.seen_log.push(label.to_string());
        true
    }

    /// Where the records stand now.
    #[cfg_attr(not(feature = "archive"), allow(dead_code))]
    fn checkpoint(&self) -> Checkpoint {
        Checkpoint {
            members: self.out.members.len(),
            skipped: self.out.skipped.len(),
            stops: self.out.stops.len(),
            directories: self.out.directories,
            filtered: self.out.filtered,
            seen: self.seen_log.len(),
        }
    }

    /// Whether a trial since `mark` broke: a container in it stopped short,
    /// or a member came out cut short. Either means the bytes were not what
    /// the archive stored, which from a password on trial means it was wrong.
    #[cfg_attr(not(feature = "archive"), allow(dead_code))]
    fn trial_broke(&self, mark: &Checkpoint) -> bool {
        self.out.stops[mark.stops..]
            .iter()
            .any(|s| matches!(s, Stop::Broken { .. }))
            || self.out.members[mark.members..]
                .iter()
                .any(|m| m.cut_short.is_some())
    }

    /// Undo everything recorded since `mark`, deleting the files it wrote.
    #[cfg_attr(not(feature = "archive"), allow(dead_code))]
    fn rollback(&mut self, mark: Checkpoint) {
        for m in self.out.members.drain(mark.members..) {
            let _ = std::fs::remove_file(&m.path);
        }
        self.out.skipped.truncate(mark.skipped);
        self.out.stops.truncate(mark.stops);
        self.out.directories = mark.directories;
        self.out.filtered = mark.filtered;
        for label in self.seen_log.drain(mark.seen..) {
            self.seen.remove(&label);
        }
    }

    /// The extraction directory, created on first use.
    fn extract_dir(&mut self) -> Option<PathBuf> {
        if let Some(d) = self.out.dir.as_ref() {
            return Some(d.path().to_path_buf());
        }
        match ExtractDir::create() {
            Ok(d) => {
                let p = d.path().to_path_buf();
                self.out.dir = Some(d);
                Some(p)
            }
            Err(e) => {
                self.fatal = Some(e);
                None
            }
        }
    }

    /// Whether the node labeled `label` can lead to the wanted member.
    fn leads_to_wanted(&self, label: &str) -> bool {
        match self.wanted {
            None => true,
            Some(w) => w == label || w.strip_prefix(label).is_some_and(|r| r.starts_with('/')),
        }
    }

    /// Record a member not read. A pointer-following walk records nothing:
    /// it is looking for one member, and the rest are not its business.
    fn skip(&mut self, label: &str, reason: SkipReason) {
        self.skip_enc(label, reason, self.encryption);
    }

    /// [`Self::skip`], for a member whose encryption is known here.
    fn skip_enc(&mut self, label: &str, reason: SkipReason, encryption: Encryption) {
        if self.wanted.is_none() {
            self.out.skipped.push(Skipped {
                label: label.to_string(),
                reason,
                encryption,
            });
        }
    }

    /// Identify one stream and unwrap it, recursing through every layer.
    fn walk(&mut self, src: &mut dyn Read, label: &str, layers: &[Layer], depth: usize) -> Flow {
        if !self.leads_to_wanted(label) {
            return Flow::Continue;
        }
        let mut head = [0u8; tar::BLOCK];
        let (n, broke) = read_head_partial(src, &mut head);
        let head = &head[..n];
        let format = sniff(head);
        if let Some(e) = broke {
            // The stream broke inside the first block. A capture's leading
            // bytes are still a capture's prefix — kept and read, the way a
            // truncated file is — but a container cut this short holds
            // nothing that can be located, and a ceiling is a ceiling.
            //
            // On trial, a break this early is the password's fault.
            if self.trial && !is_ceiling(&e) {
                self.rejected = true;
                return Flow::Continue;
            }
            if n == 0 || is_ceiling(&e) || !matches!(format, Format::Pcap | Format::Pcapng) {
                return self.broken(label, &e);
            }
            return self.write_member(&mut &head[..], label, layers, format, Some(e.to_string()));
        }
        let mut chained = head.chain(src);
        match format {
            Format::Empty => {
                self.skip(label, SkipReason::Empty);
                Flow::Continue
            }
            Format::Pcap | Format::Pcapng => {
                self.write_member(&mut chained, label, layers, format, None)
            }
            Format::Gzip | Format::Tar if depth >= self.limits.max_depth => {
                self.skip(label, SkipReason::TooDeep);
                Flow::Continue
            }
            #[cfg(feature = "archive")]
            Format::Zip if depth >= self.limits.max_depth => {
                self.skip(label, SkipReason::TooDeep);
                Flow::Continue
            }
            Format::Gzip => {
                // A gzip layer keeps its label: `x.pcap.gz` names one capture,
                // and the compression is a property of how it was shipped.
                let mut inner = Inflating {
                    inner: flate2::read::MultiGzDecoder::new(chained),
                    used: std::rc::Rc::clone(&self.used),
                    limit: self.limits.max_inflated_bytes,
                };
                let mut next = layers.to_vec();
                next.push(Layer::Gzip);
                self.walk(&mut inner, label, &next, depth + 1)
            }
            Format::Tar => {
                let mut next = layers.to_vec();
                next.push(Layer::Tar);
                self.walk_tar(&mut chained, label, &next, depth + 1)
            }
            #[cfg(feature = "archive")]
            Format::Zip => self.walk_zip(&mut chained, label, layers, depth + 1),
            #[cfg(not(feature = "archive"))]
            Format::Zip => {
                self.skip(label, SkipReason::Unsupported(format));
                Flow::Continue
            }
            Format::SevenZip | Format::Zstd | Format::Xz | Format::Bzip2 | Format::Lz4 => {
                self.skip(label, SkipReason::Unsupported(format));
                Flow::Continue
            }
            Format::Unknown => {
                // On trial, bytes that are no capture are either a member that
                // is not one, or a wrong password ZipCrypto's check byte let
                // through. The member's own CRC or MAC, checked at its end,
                // tells the two apart.
                if self.trial {
                    match io::copy(&mut chained, &mut io::sink()) {
                        Err(e) if is_ceiling(&e) => return self.broken(label, &e),
                        Err(_) => {
                            self.rejected = true;
                            return Flow::Continue;
                        }
                        Ok(_) => {}
                    }
                }
                let hex: Vec<String> = head.iter().take(4).map(|b| format!("{b:02x}")).collect();
                self.skip(
                    label,
                    SkipReason::NotACapture {
                        head: hex.join(" "),
                    },
                );
                Flow::Continue
            }
        }
    }
    /// Walk the entries of one tar archive.
    fn walk_tar(
        &mut self,
        src: &mut dyn Read,
        label: &str,
        layers: &[Layer],
        depth: usize,
    ) -> Flow {
        let mut tar = tar::TarReader::new(src);
        loop {
            let header = match tar.next_entry() {
                Ok(Some(h)) => h,
                Ok(None) => return Flow::Continue,
                Err(tar::TarError::Io(e)) => return self.broken(label, &e),
                Err(e) => {
                    if self.trial {
                        self.rejected = true;
                        return Flow::Continue;
                    }
                    self.out.stops.push(Stop::Broken {
                        container: label.to_string(),
                        detail: e.to_string(),
                    });
                    // The container is unreadable past here, but an OUTER
                    // archive may still hold more members after it.
                    return Flow::Continue;
                }
            };
            self.entries += 1;
            if self.entries > self.limits.max_entries {
                self.out.stops.push(Stop::EntryCap {
                    limit: self.limits.max_entries,
                });
                return Flow::Abort;
            }
            let child = format!("{label}/{}", member_name(&header.name));
            let reason = match header.kind {
                tar::EntryKind::File => None,
                tar::EntryKind::Directory => {
                    if self.wanted.is_none() {
                        self.out.directories += 1;
                    }
                    continue;
                }
                tar::EntryKind::HardLink | tar::EntryKind::SymLink => Some(SkipReason::Link),
                tar::EntryKind::CharDevice | tar::EntryKind::BlockDevice | tar::EntryKind::Fifo => {
                    Some(SkipReason::Special)
                }
                tar::EntryKind::Sparse => Some(SkipReason::Sparse),
                tar::EntryKind::Other(t) => Some(SkipReason::OtherType(t)),
            };
            if let Some(reason) = reason {
                self.skip(&child, reason);
                continue;
            }
            if !self.claim(&child) {
                self.skip(&child, SkipReason::DuplicateName);
                continue;
            }
            if let Some(keep) = self.keep {
                let file_name = child.rsplit('/').next().unwrap_or(&child);
                if !keep(file_name) {
                    self.out.filtered += 1;
                    continue;
                }
            }
            if self.walk(&mut tar.data(), &child, layers, depth) == Flow::Abort {
                return Flow::Abort;
            }
            if self.wanted.is_some() && !self.out.members.is_empty() {
                // Found what the pointer names; the rest is not needed.
                return Flow::Abort;
            }
        }
    }

    /// Copy one capture out to a file this walker names.
    fn write_member(
        &mut self,
        src: &mut dyn Read,
        label: &str,
        layers: &[Layer],
        format: Format,
        already_cut: Option<String>,
    ) -> Flow {
        if self.wanted.is_some_and(|w| w != label) {
            return Flow::Continue;
        }
        let Some(dir) = self.extract_dir() else {
            return Flow::Abort;
        };
        let ext = if format == Format::Pcapng {
            "pcapng"
        } else {
            "pcap"
        };
        let path = dir.join(format!("m{:05}.{ext}", self.members_written));
        self.members_written += 1;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        // Owner-only, whatever the umask: the member may be decrypted capture
        // data, and the directory's own 0700 is not the only line.
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(&path);
        let mut file = match file {
            Ok(f) => io::BufWriter::new(f),
            Err(e) => {
                self.out.stops.push(Stop::WriteFailed {
                    at: label.to_string(),
                    detail: e.to_string(),
                });
                return Flow::Abort;
            }
        };
        let copied = io::copy(src, &mut file);
        let flushed = io::Write::flush(&mut file);
        let cut_short = match (copied, flushed) {
            (Ok(_), Ok(())) => already_cut,
            (Err(e), _) if is_ceiling(&e) => {
                drop(file);
                let _ = std::fs::remove_file(&path);
                self.out.stops.push(Stop::InflationCap {
                    limit: self.limits.max_inflated_bytes,
                    at: label.to_string(),
                });
                return Flow::Abort;
            }
            // The data broke off: the archive was cut short, or a gzip layer
            // is corrupt. What arrived is a capture's prefix and is kept, the
            // way libpcap keeps the packets of a truncated file.
            //
            // Not on trial: there a break means the password was wrong, and
            // what arrived is not the member at all.
            (Err(_), _) if self.trial => {
                drop(file);
                let _ = std::fs::remove_file(&path);
                self.rejected = true;
                return Flow::Continue;
            }
            (Err(e), _)
                if matches!(
                    e.kind(),
                    io::ErrorKind::UnexpectedEof
                        | io::ErrorKind::InvalidInput
                        | io::ErrorKind::InvalidData
                ) =>
            {
                Some(e.to_string())
            }
            (Err(e), _) | (Ok(_), Err(e)) => {
                drop(file);
                let _ = std::fs::remove_file(&path);
                self.out.stops.push(Stop::WriteFailed {
                    at: label.to_string(),
                    detail: e.to_string(),
                });
                return Flow::Abort;
            }
        };
        self.out.members.push(Member {
            label: label.to_string(),
            path,
            layers: layers.to_vec(),
            cut_short,
            encryption: self.encryption,
        });
        Flow::Continue
    }

    /// Record that the stream feeding `label` broke, and stop: nothing after
    /// a broken read can be located.
    fn broken(&mut self, label: &str, e: &io::Error) -> Flow {
        if self.trial && !is_ceiling(e) {
            self.rejected = true;
            return Flow::Continue;
        }
        if is_ceiling(e) {
            self.out.stops.push(Stop::InflationCap {
                limit: self.limits.max_inflated_bytes,
                at: label.to_string(),
            });
        } else {
            self.out.stops.push(Stop::Broken {
                container: label.to_string(),
                detail: e.to_string(),
            });
        }
        Flow::Abort
    }
}

/// A private directory holding extracted members, deleted on drop.
///
/// Created mode `0700` under the system temp directory with a name no one
/// else chose. It holds an exclusive lock on a file inside itself for as long
/// as it lives; the lock dies with the process however the process dies. So a
/// directory whose lock can be taken belongs to nobody, and
/// [`ExtractDir::create`] removes such directories before making its own.
/// That is what cleans up after a run that ended in `std::process::exit`,
/// which runs no destructors, or in a crash.
#[derive(Debug)]
pub struct ExtractDir {
    /// Held open, and exclusively locked, for the directory's lifetime. First
    /// so it closes before the directory is removed.
    _lock: std::fs::File,
    /// The directory, removed with its contents on drop.
    dir: tempfile::TempDir,
}

/// Name prefix of every extraction directory, which is what the sweep looks
/// for.
pub const DIR_PREFIX: &str = "sipnab-archive-";

/// The lock file inside each extraction directory.
const LOCK_NAME: &str = ".owner.lock";

impl ExtractDir {
    /// Create a fresh directory under `root`, after removing any abandoned
    /// ones there.
    ///
    /// # Errors
    ///
    /// When the directory or its lock file cannot be created.
    pub fn create_in(root: &Path) -> io::Result<Self> {
        let dir = tempfile::Builder::new()
            .prefix(DIR_PREFIX)
            .tempdir_in(root)?;
        let lock = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(dir.path().join(LOCK_NAME))?;
        lock.try_lock().map_err(|e| match e {
            std::fs::TryLockError::Error(e) => e,
            std::fs::TryLockError::WouldBlock => {
                io::Error::other("a freshly created lock file is already locked")
            }
        })?;
        let removed = sweep_abandoned(root, dir.path());
        if removed > 0 {
            tracing::info!(
                "Removed {removed} extraction director(ies) left in '{}' by earlier runs \
                 that ended without cleaning up",
                root.display()
            );
        }
        Ok(Self { _lock: lock, dir })
    }

    /// [`Self::create_in`] the system temp directory.
    ///
    /// # Errors
    ///
    /// As [`Self::create_in`].
    pub fn create() -> io::Result<Self> {
        let dir = Self::create_in(&std::env::temp_dir())?;
        Ok(dir)
    }

    /// The directory's path.
    #[must_use]
    pub fn path(&self) -> &Path {
        self.dir.path()
    }
}

/// Remove extraction directories under `root` whose owner is gone, returning
/// how many were removed.
///
/// A directory is removed only when it is a real directory (never a symlink
/// someone planted with our prefix), is owned by the same user as `ours`, and
/// its lock can be taken — which is possible only once the process that held
/// it has exited. `ours` is never touched.
pub fn sweep_abandoned(root: &Path, ours: &Path) -> usize {
    let Ok(ours_meta) = std::fs::symlink_metadata(ours) else {
        return 0;
    };
    let Ok(entries) = std::fs::read_dir(root) else {
        return 0;
    };
    let mut removed = 0;
    for entry in entries.flatten() {
        let path = entry.path();
        let named_ours = entry
            .file_name()
            .to_str()
            .is_some_and(|n| n.starts_with(DIR_PREFIX));
        if !named_ours || path == ours {
            continue;
        }
        // symlink_metadata: a planted symlink is its own type, never a dir.
        let Ok(meta) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if !meta.is_dir() || !same_owner(&meta, &ours_meta) {
            continue;
        }
        let Ok(lock) = std::fs::File::open(path.join(LOCK_NAME)) else {
            // No lock file: another process is between creating the directory
            // and its lock, or crashed in that instant. Only the second is
            // ours to clean, and only age tells them apart.
            let stale = meta
                .modified()
                .ok()
                .and_then(|t| t.elapsed().ok())
                .is_some_and(|age| age > std::time::Duration::from_secs(3600));
            if stale && std::fs::remove_dir_all(&path).is_ok() {
                removed += 1;
            }
            continue;
        };
        if lock.try_lock().is_ok() {
            drop(lock);
            if std::fs::remove_dir_all(&path).is_ok() {
                removed += 1;
            }
        }
    }
    removed
}

/// Whether two files belong to the same user.
#[cfg(unix)]
fn same_owner(a: &std::fs::Metadata, b: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    a.uid() == b.uid()
}

/// Whether two files belong to the same user. Without Unix ownership, the
/// per-user temp directory is the only boundary, and it already holds.
#[cfg(not(unix))]
fn same_owner(_a: &std::fs::Metadata, _b: &std::fs::Metadata) -> bool {
    true
}

/// An extraction directory held so its members can be read, with their
/// labels registered for the readers that stamp a source name.
#[derive(Debug)]
pub struct KeptExtraction {
    /// Extracted member files, whose labels are registered.
    paths: Vec<PathBuf>,
    /// Of those, the ones decrypted with a password, registered in
    /// [`DECRYPTED`] for as long as this extraction lives.
    decrypted: Vec<PathBuf>,
    /// The directory itself. Dropped after the labels are withdrawn.
    _dir: ExtractDir,
}

impl KeptExtraction {
    /// Hold `dir`, and register each `(file, label)` so a reader names the
    /// file by its label.
    #[must_use]
    pub fn new(dir: ExtractDir, labels: Vec<(PathBuf, String)>) -> Self {
        let mut map = LABELS.write();
        let mut paths = Vec::with_capacity(labels.len());
        for (path, label) in labels {
            map.insert(path.clone(), std::sync::Arc::from(label));
            paths.push(path);
        }
        Self {
            paths,
            decrypted: Vec::new(),
            _dir: dir,
        }
    }

    /// Record which of this extraction's files were decrypted with a
    /// password, so a writer of their data can say it is writing them out
    /// unencrypted.
    #[must_use]
    pub fn with_decrypted(mut self, decrypted: Vec<PathBuf>) -> Self {
        let mut set = DECRYPTED.write();
        for p in &decrypted {
            set.insert(p.clone());
        }
        drop(set);
        self.decrypted = decrypted;
        self
    }

    /// The directory the members were extracted into.
    #[must_use]
    pub fn dir(&self) -> &Path {
        self._dir.path()
    }
}

impl Drop for KeptExtraction {
    fn drop(&mut self) {
        // Withdrawn BEFORE the directory goes (fields drop after this body),
        // so no reader can be told a label for a file that no longer exists.
        let mut map = LABELS.write();
        for p in &self.paths {
            map.remove(p);
        }
        drop(map);
        let mut set = DECRYPTED.write();
        for p in &self.decrypted {
            set.remove(p);
        }
    }
}

/// Extracted member files decrypted with a password. See
/// [`KeptExtraction::with_decrypted`].
static DECRYPTED: std::sync::LazyLock<parking_lot::RwLock<std::collections::HashSet<PathBuf>>> =
    std::sync::LazyLock::new(|| parking_lot::RwLock::new(std::collections::HashSet::new()));

/// Whether `path` is an archive member that was decrypted with a password.
#[must_use]
pub fn is_decrypted_member(path: &Path) -> bool {
    DECRYPTED.read().contains(path)
}

/// Outputs already warned about by [`warn_decrypted_export`].
static EXPORT_WARNED: parking_lot::Mutex<Vec<PathBuf>> = parking_lot::Mutex::new(Vec::new());

/// The warning a writer gives before it writes data decrypted from a
/// password-protected archive, unencrypted, to `output`.
#[must_use]
pub fn decrypted_export_warning(flag: &str, output: &Path) -> String {
    format!(
        "{flag} '{}' receives capture data decrypted from a password-protected archive, \
         and writes it unencrypted. Protect or delete it as you would the unpacked archive.",
        output.display()
    )
}

/// Warn, once per output, that `output` receives decrypted data.
pub fn warn_decrypted_export(flag: &str, output: &Path) {
    let mut warned = EXPORT_WARNED.lock();
    if warned.iter().any(|p| p == output) {
        return;
    }
    warned.push(output.to_path_buf());
    drop(warned);
    tracing::warn!("{}", decrypted_export_warning(flag, output));
}

/// Extracted member file -> the label it goes by.
///
/// Process-global because the readers that stamp a packet's source name —
/// the `-I` file reader, the `--cores` reader, the log lines around them —
/// are handed a path and nothing else, and threading a label through every
/// one of them would be a second channel for a fact the path already
/// identifies. Keys are files this module created under names it chose, so
/// no two extractions can collide in it.
static LABELS: std::sync::LazyLock<
    parking_lot::RwLock<std::collections::HashMap<PathBuf, std::sync::Arc<str>>>,
> = std::sync::LazyLock::new(|| parking_lot::RwLock::new(std::collections::HashMap::new()));

/// Extractions held for the life of a CLI run. See [`keep_for_run`].
static RUN: parking_lot::Mutex<Vec<KeptExtraction>> = parking_lot::Mutex::new(Vec::new());

/// Hold an extraction for the rest of the run.
///
/// The `-I` set is read by a capture thread, re-read for embedded TLS secrets,
/// and mapped by `--cores` workers, none of which report back when they are
/// done with a file. So its members stay until [`release_run`], which the run
/// calls on its way out. A run that leaves without calling it — a crash, a
/// signal, an early `std::process::exit` — leaves a directory whose lock died
/// with it, and the next extraction's sweep removes that.
pub fn keep_for_run(kept: KeptExtraction) {
    RUN.lock().push(kept);
}

/// Delete everything [`keep_for_run`] held. Safe to call more than once.
pub fn release_run() {
    let held = std::mem::take(&mut *RUN.lock());
    drop(held);
    // The run is ending: clear every archive password it held rather than
    // leave them for the process's teardown, which never drops a static.
    #[cfg(feature = "archive")]
    password::clear_run_keyring();
}

/// [`release_run`], then `std::process::exit`.
///
/// `std::process::exit` runs no destructors, so a run that exits through it
/// with members extracted would leave them on disk until the next
/// extraction's sweep. Every exit a run can take after resolving its input
/// goes through here instead.
pub fn release_run_and_exit(code: i32) -> ! {
    release_run();
    std::process::exit(code)
}

/// [`release_run`] from inside the panic hook, where blocking is not an
/// option: the panic may have happened with either lock held on this very
/// thread. Takes the run's extractions only if the lock is free, and deletes
/// their directories without touching the label map.
pub fn release_run_on_panic() {
    let Some(mut held) = RUN.try_lock() else {
        return;
    };
    for kept in std::mem::take(&mut *held) {
        let _ = std::fs::remove_dir_all(kept.dir());
        // Its Drop would take the label lock; the directory is already gone,
        // and the process is about to be.
        std::mem::forget(kept);
    }
}

/// Directories holding this run's extracted members, for the path sandbox,
/// which must let the capture thread read them and let the run delete them.
#[must_use]
pub fn run_extraction_dirs() -> Vec<PathBuf> {
    RUN.lock().iter().map(|k| k.dir().to_path_buf()).collect()
}

/// The name a capture file goes by: its archive label when it is an extracted
/// member, otherwise its path.
#[must_use]
pub fn source_name(path: &Path) -> String {
    match LABELS.read().get(path) {
        Some(label) => label.to_string(),
        None => path.display().to_string(),
    }
}

/// [`source_name`] as the shared string a packet's source is stamped with.
#[must_use]
pub fn source_arc(path: &Path) -> std::sync::Arc<str> {
    match LABELS.read().get(path) {
        Some(label) => std::sync::Arc::clone(label),
        None => std::sync::Arc::from(path.display().to_string()),
    }
}

/// Whether `path` is an extracted archive member rather than a file the
/// operator named.
#[must_use]
pub fn is_extracted_member(path: &Path) -> bool {
    LABELS.read().contains_key(path)
}

#[cfg(test)]
mod tests {
    use super::tar::testutil::{Spec, build};
    use super::*;
    use std::io::Write;

    /// A one-packet classic pcap: global header plus one record.
    fn pcap_bytes(payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&0xa1b2_c3d4u32.to_le_bytes());
        out.extend_from_slice(&2u16.to_le_bytes());
        out.extend_from_slice(&4u16.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&65535u32.to_le_bytes());
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(&1_700_000_000u32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        out.extend_from_slice(payload);
        out
    }

    fn gzip(data: &[u8]) -> Vec<u8> {
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(data).expect("gzip");
        enc.finish().expect("gzip")
    }

    fn limits() -> Limits {
        Limits {
            max_inflated_bytes: 64 * 1024 * 1024,
            max_entries: MAX_ENTRIES,
            max_depth: MAX_DEPTH,
        }
    }

    fn write(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, bytes).expect("write");
        p
    }

    fn labels(exp: &Expansion) -> Vec<String> {
        exp.members.iter().map(|m| m.label.clone()).collect()
    }

    #[test]
    fn sniff_names_every_format_by_its_magic() {
        let cases: &[(&[u8], Format)] = &[
            (&[0xd4, 0xc3, 0xb2, 0xa1, 2, 0], Format::Pcap),
            (&[0xa1, 0xb2, 0xc3, 0xd4, 0, 2], Format::Pcap),
            (&[0x4d, 0x3c, 0xb2, 0xa1, 2, 0], Format::Pcap),
            (&[0xa1, 0xb2, 0x3c, 0x4d, 0, 2], Format::Pcap),
            (&[0x0a, 0x0d, 0x0d, 0x0a, 0, 0], Format::Pcapng),
            (&[0x1f, 0x8b, 0x08, 0x00], Format::Gzip),
            (b"PK\x03\x04rest", Format::Zip),
            (b"PK\x05\x06rest", Format::Zip),
            (&[b'7', b'z', 0xbc, 0xaf, 0x27, 0x1c], Format::SevenZip),
            (&[0x28, 0xb5, 0x2f, 0xfd, 0], Format::Zstd),
            (&[0xfd, b'7', b'z', b'X', b'Z', 0x00], Format::Xz),
            (b"BZh91AY", Format::Bzip2),
            (&[0x04, 0x22, 0x4d, 0x18, 0], Format::Lz4),
            (b"", Format::Empty),
            (b"hello, world", Format::Unknown),
            (b"BZh", Format::Unknown),
        ];
        for (head, want) in cases {
            assert_eq!(sniff(head), *want, "{head:02x?}");
        }
        let tar = build(&[Spec::file("a", b"x")]);
        assert_eq!(sniff(&tar[..512]), Format::Tar);
        assert_eq!(
            sniff(&tar[..100]),
            Format::Unknown,
            "a partial block is not a tar"
        );
    }

    /// The whole reason this module exists: the members of a `.tgz` come out
    /// as captures, with labels naming the archive and the member.
    #[test]
    fn a_tgz_of_captures_expands_to_its_members() {
        let tmp = tempfile::tempdir().expect("tmp");
        let a = pcap_bytes(b"alpha");
        let b = pcap_bytes(b"bravo");
        let tar = build(&[
            Spec::dir("set/"),
            Spec::file("set/a.pcap", &a),
            Spec::file("set/b.pcap", &b),
        ]);
        let tgz = write(tmp.path(), "set.tgz", &gzip(&tar));
        let exp = expand(&tgz, &limits()).expect("expand");
        let root = tgz.display().to_string();
        assert_eq!(
            labels(&exp),
            vec![format!("{root}/set/a.pcap"), format!("{root}/set/b.pcap")]
        );
        assert_eq!(exp.directories, 1);
        assert!(exp.skipped.is_empty(), "{:?}", exp.skipped);
        assert!(exp.stops.is_empty(), "{:?}", exp.stops);
        assert_eq!(exp.members[0].layers, vec![Layer::Gzip, Layer::Tar]);
        assert_eq!(std::fs::read(&exp.members[0].path).expect("read"), a);
        assert_eq!(std::fs::read(&exp.members[1].path).expect("read"), b);
    }

    /// Plain `.tar`, and a `.pcap.gz` that is merely compressed, go through
    /// the same walk.
    #[test]
    fn a_plain_tar_and_a_single_gzip_use_the_same_walk() {
        let tmp = tempfile::tempdir().expect("tmp");
        let cap = pcap_bytes(b"x");
        let tar = write(tmp.path(), "set.tar", &build(&[Spec::file("x.pcap", &cap)]));
        let exp = expand(&tar, &limits()).expect("tar");
        assert_eq!(labels(&exp), vec![format!("{}/x.pcap", tar.display())]);
        assert_eq!(exp.members[0].layers, vec![Layer::Tar]);

        let gz = write(tmp.path(), "one.pcap.gz", &gzip(&cap));
        let exp = expand(&gz, &limits()).expect("gz");
        assert_eq!(
            labels(&exp),
            vec![gz.display().to_string()],
            "a compressed capture keeps its own name: there is no member to name"
        );
        assert_eq!(exp.members[0].layers, vec![Layer::Gzip]);
        assert_eq!(std::fs::read(&exp.members[0].path).expect("read"), cap);
    }

    /// Every member that is not a capture is accounted for with its reason,
    /// and none of them stops the rest being read.
    #[test]
    fn every_non_capture_member_is_skipped_with_its_reason() {
        let tmp = tempfile::tempdir().expect("tmp");
        let cap = pcap_bytes(b"ok");
        let tar = build(&[
            Spec::file("empty.pcap", b""),
            Spec::file("README.txt", b"notes about the capture"),
            Spec {
                name: b"link.pcap",
                typeflag: b'2',
                data: &[],
                size_field: None,
            },
            Spec {
                name: b"dev",
                typeflag: b'3',
                data: &[],
                size_field: None,
            },
            Spec::file("zst.pcap.zst", &[0x28, 0xb5, 0x2f, 0xfd, 1, 2, 3]),
            Spec::file("inner.zip", b"PK\x03\x04zipzip"),
            Spec::file("good.pcap", &cap),
        ]);
        let path = write(tmp.path(), "mixed.tar", &tar);
        let exp = expand(&path, &limits()).expect("expand");
        let root = path.display();
        assert_eq!(labels(&exp), vec![format!("{root}/good.pcap")]);
        let reasons: Vec<(String, SkipReason)> = exp
            .skipped
            .iter()
            .map(|s| (s.label.clone(), s.reason.clone()))
            .collect();
        assert_eq!(
            reasons,
            vec![
                (format!("{root}/empty.pcap"), SkipReason::Empty),
                (
                    format!("{root}/README.txt"),
                    SkipReason::NotACapture {
                        head: "6e 6f 74 65".to_string()
                    }
                ),
                (format!("{root}/link.pcap"), SkipReason::Link),
                (format!("{root}/dev"), SkipReason::Special),
                (
                    format!("{root}/zst.pcap.zst"),
                    SkipReason::Unsupported(Format::Zstd)
                ),
                #[cfg(not(feature = "archive"))]
                (
                    format!("{root}/inner.zip"),
                    SkipReason::Unsupported(Format::Zip)
                ),
            ]
        );
        // With ZIP support the stub is opened, and a ZIP with no central
        // directory is a container that could not be read, said as such.
        #[cfg(feature = "archive")]
        assert!(
            matches!(exp.stops.as_slice(), [Stop::Broken { container, .. }]
                if container.ends_with("/inner.zip")),
            "{:?}",
            exp.stops
        );
        #[cfg(not(feature = "archive"))]
        assert!(exp.stops.is_empty());
    }

    /// A trial that fails takes back everything it recorded: the members it
    /// wrote, their files, its skips and stops, and the labels it claimed.
    #[test]
    fn a_rolled_back_trial_leaves_nothing_behind() {
        let tmp = tempfile::tempdir().expect("tmp");
        let root = tmp.path().join("r");
        let lim = limits();
        let mut w = Walker::new(&lim, None, &root, "r");
        let kept = pcap_bytes(b"kept");
        assert_eq!(
            w.write_member(&mut &kept[..], "r/kept", &[], Format::Pcap, None),
            Flow::Continue
        );
        assert!(w.claim("r/kept"));
        let mark = w.checkpoint();
        let gone = pcap_bytes(b"gone");
        assert!(w.claim("r/gone"));
        let _ = w.write_member(&mut &gone[..], "r/gone", &[], Format::Pcap, None);
        w.skip("r/other", SkipReason::Empty);
        w.out.stops.push(Stop::Broken {
            container: "r".into(),
            detail: "x".into(),
        });
        let written = w.out.members[1].path.clone();
        assert!(w.trial_broke(&mark));
        w.rollback(mark);
        assert_eq!(labels(&w.out), vec!["r/kept".to_string()]);
        assert!(w.out.skipped.is_empty() && w.out.stops.is_empty());
        assert!(!written.exists(), "the trial's file is deleted");
        assert!(w.claim("r/gone"), "the trial's label is free again");
        assert!(!w.claim("r/kept"));
    }

    /// On trial, a member whose stream fails in any way is the password's
    /// fault: the trial is rejected and nothing is recorded, rather than the
    /// whole walk ending on a write failure.
    #[test]
    fn a_stream_failure_on_trial_rejects_rather_than_stops() {
        struct Failing(Vec<u8>);
        impl Read for Failing {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                if self.0.is_empty() {
                    return Err(io::Error::other("authentication failed"));
                }
                let n = buf.len().min(self.0.len());
                buf[..n].copy_from_slice(&self.0[..n]);
                self.0.drain(..n);
                Ok(n)
            }
        }
        let tmp = tempfile::tempdir().expect("tmp");
        let root = tmp.path().join("r");
        let lim = limits();
        let mut w = Walker::new(&lim, None, &root, "r");
        w.trial = true;
        let flow = w.write_member(
            &mut Failing(pcap_bytes(b"x")),
            "r/m",
            &[],
            Format::Pcap,
            None,
        );
        assert_eq!(flow, Flow::Continue);
        assert!(w.rejected);
        assert!(w.out.members.is_empty() && w.out.stops.is_empty());
    }

    /// Two layers of compression and archiving inside each other: a
    /// `.pcap.gz` member of a tar inside a `.tgz`.
    #[test]
    fn nested_layers_are_unwrapped_and_labeled_by_their_path() {
        let tmp = tempfile::tempdir().expect("tmp");
        let cap = pcap_bytes(b"deep");
        let inner = build(&[Spec::file("ring/x.pcap.gz", &gzip(&cap))]);
        let outer = build(&[Spec::file("inner.tar", &inner)]);
        let path = write(tmp.path(), "outer.tgz", &gzip(&outer));
        let exp = expand(&path, &limits()).expect("expand");
        assert_eq!(
            labels(&exp),
            vec![format!("{}/inner.tar/ring/x.pcap.gz", path.display())]
        );
        assert_eq!(
            exp.members[0].layers,
            vec![Layer::Gzip, Layer::Tar, Layer::Tar, Layer::Gzip]
        );
        assert_eq!(std::fs::read(&exp.members[0].path).expect("read"), cap);
    }

    /// A member named to climb out of the extraction directory lands inside
    /// it, under a name this module chose, and nothing is written anywhere
    /// else.
    #[test]
    fn a_member_name_never_becomes_a_path() {
        let tmp = tempfile::tempdir().expect("tmp");
        let victim_dir = tmp.path().join("victim");
        std::fs::create_dir(&victim_dir).expect("mkdir");
        let cap = pcap_bytes(b"x");
        let evil = format!("../../../../{}/owned.pcap", victim_dir.display());
        let tar = build(&[Spec::file(&evil, &cap), Spec::file("/etc/abs.pcap", &cap)]);
        let path = write(tmp.path(), "evil.tar", &tar);
        let exp = expand(&path, &limits()).expect("expand");
        assert_eq!(exp.members.len(), 2);
        let dir = exp.dir.as_ref().expect("dir").path().to_path_buf();
        for m in &exp.members {
            assert_eq!(m.path.parent(), Some(dir.as_path()), "{m:?}");
            let file = m.path.file_name().and_then(|n| n.to_str()).expect("name");
            assert!(file.starts_with('m') && !file.contains("owned"), "{file}");
        }
        assert_eq!(
            std::fs::read_dir(&victim_dir).expect("ls").count(),
            0,
            "nothing written outside the extraction directory"
        );
    }

    /// A gzip bomb is refused having written no more than the ceiling, and the
    /// refusal says where and why.
    #[test]
    fn a_decompression_bomb_stops_at_the_ceiling() {
        let tmp = tempfile::tempdir().expect("tmp");
        // A pcap header followed by 8 MiB of zeros compresses to ~8 KiB.
        let mut big = pcap_bytes(b"");
        big.resize(8 * 1024 * 1024, 0);
        let path = write(tmp.path(), "bomb.pcap.gz", &gzip(&gzip(&big)));
        let tight = Limits {
            max_inflated_bytes: 1024 * 1024,
            ..limits()
        };
        let exp = expand(&path, &tight).expect("expand");
        assert!(
            exp.members.is_empty(),
            "the member being written is discarded"
        );
        assert!(
            matches!(&exp.stops[..], [Stop::InflationCap { limit, .. }] if *limit == 1024 * 1024),
            "{:?}",
            exp.stops
        );
        let written: u64 = exp
            .dir
            .as_ref()
            .map(|d| {
                std::fs::read_dir(d.path())
                    .expect("ls")
                    .filter_map(Result::ok)
                    .filter_map(|e| e.metadata().ok())
                    .map(|m| m.len())
                    .sum()
            })
            .unwrap_or(0);
        assert!(
            written <= 1024 * 1024,
            "wrote {written} bytes past the ceiling"
        );
    }

    #[test]
    fn nesting_past_the_depth_limit_is_refused() {
        let tmp = tempfile::tempdir().expect("tmp");
        let mut data = pcap_bytes(b"x");
        for _ in 0..(MAX_DEPTH + 1) {
            data = gzip(&data);
        }
        let path = write(tmp.path(), "deep.gz", &data);
        let exp = expand(&path, &limits()).expect("expand");
        assert!(exp.members.is_empty());
        assert_eq!(exp.skipped.len(), 1);
        assert_eq!(exp.skipped[0].reason, SkipReason::TooDeep);
    }

    #[test]
    fn the_entry_cap_stops_the_walk_and_says_so() {
        let tmp = tempfile::tempdir().expect("tmp");
        let cap = pcap_bytes(b"x");
        let names: Vec<String> = (0..5).map(|i| format!("{i}.pcap")).collect();
        let specs: Vec<Spec<'_>> = names.iter().map(|n| Spec::file(n, &cap)).collect();
        let path = write(tmp.path(), "many.tar", &build(&specs));
        let few = Limits {
            max_entries: 3,
            ..limits()
        };
        let exp = expand(&path, &few).expect("expand");
        assert_eq!(exp.members.len(), 3);
        assert_eq!(exp.stops, vec![Stop::EntryCap { limit: 3 }]);
    }

    /// A truncated archive keeps what arrived, marks the member it broke off
    /// inside, and records that the walk ended there.
    #[test]
    fn a_truncated_archive_keeps_what_arrived() {
        let tmp = tempfile::tempdir().expect("tmp");
        let a = pcap_bytes(b"whole");
        let mut b = pcap_bytes(b"");
        b.resize(3000, 0xab);
        let tar = build(&[Spec::file("a.pcap", &a), Spec::file("b.pcap", &b)]);
        // Cut inside b's data: header(512) + a(512) + b header(512) + 1000.
        let path = write(tmp.path(), "cut.tar", &tar[..512 * 3 + 1000]);
        let exp = expand(&path, &limits()).expect("expand");
        assert_eq!(exp.members.len(), 2);
        assert!(exp.members[0].cut_short.is_none());
        assert!(exp.members[1].cut_short.is_some(), "{:?}", exp.members[1]);
        assert_eq!(
            std::fs::metadata(&exp.members[1].path).expect("meta").len(),
            1000
        );
        assert!(exp.lossy());
    }

    /// A member cut off inside its FIRST block still keeps what arrived. The
    /// walk reads a block to identify a stream, and that read hitting the cut
    /// used to discard the member as though it were never there.
    #[test]
    fn a_member_cut_inside_its_first_block_is_still_kept() {
        let tmp = tempfile::tempdir().expect("tmp");
        let a = pcap_bytes(b"whole");
        let mut b = pcap_bytes(b"");
        b.resize(3000, 0xab);
        let tar = build(&[Spec::file("a.pcap", &a), Spec::file("b.pcap", &b)]);
        let path = write(tmp.path(), "cut.tgz", &gzip(&tar[..512 * 3 + 100]));
        let exp = expand(&path, &limits()).expect("expand");
        assert_eq!(exp.members.len(), 2, "{exp:?}");
        assert!(exp.members[1].cut_short.is_some(), "{:?}", exp.members[1]);
        assert_eq!(
            std::fs::metadata(&exp.members[1].path).expect("meta").len(),
            100
        );
    }

    #[test]
    fn a_corrupt_header_ends_the_walk_but_keeps_earlier_members() {
        let tmp = tempfile::tempdir().expect("tmp");
        let cap = pcap_bytes(b"x");
        let mut tar = build(&[Spec::file("a.pcap", &cap), Spec::file("b.pcap", &cap)]);
        tar[1024 + 3] ^= 0x55;
        let path = write(tmp.path(), "bent.tar", &tar);
        let exp = expand(&path, &limits()).expect("expand");
        assert_eq!(exp.members.len(), 1);
        assert!(
            matches!(&exp.stops[..], [Stop::Broken { .. }]),
            "{:?}",
            exp.stops
        );
    }

    #[test]
    fn a_repeated_member_name_is_read_once() {
        let tmp = tempfile::tempdir().expect("tmp");
        let first = pcap_bytes(b"first");
        let second = pcap_bytes(b"second");
        let tar = build(&[Spec::file("x.pcap", &first), Spec::file("x.pcap", &second)]);
        let path = write(tmp.path(), "dup.tar", &tar);
        let exp = expand(&path, &limits()).expect("expand");
        assert_eq!(exp.members.len(), 1);
        assert_eq!(std::fs::read(&exp.members[0].path).expect("read"), first);
        assert_eq!(exp.skipped[0].reason, SkipReason::DuplicateName);
    }

    /// Following a pointer extracts exactly the member it names, through
    /// every layer, and nothing else.
    #[test]
    fn extract_member_finds_the_member_a_label_names() {
        let tmp = tempfile::tempdir().expect("tmp");
        let a = pcap_bytes(b"alpha");
        let b = pcap_bytes(b"bravo");
        let inner = build(&[Spec::file("b.pcap.gz", &gzip(&b))]);
        let outer = build(&[Spec::file("a.pcap", &a), Spec::file("in.tar", &inner)]);
        let path = write(tmp.path(), "o.tgz", &gzip(&outer));
        let root = path.display().to_string();

        let (m, dir) = extract_member(&path, &format!("{root}/in.tar/b.pcap.gz"), &limits())
            .expect("walk")
            .expect("found");
        assert_eq!(std::fs::read(&m.path).expect("read"), b);
        assert_eq!(
            std::fs::read_dir(dir.path())
                .expect("ls")
                .filter_map(Result::ok)
                .filter(|e| e.file_name() != LOCK_NAME)
                .count(),
            1,
            "only the named member is written"
        );
        assert!(
            extract_member(&path, &format!("{root}/nope.pcap"), &limits())
                .expect("walk")
                .is_none()
        );
    }

    /// The names a file browser and MCP `list_captures` offer: captures,
    /// compressed captures, and archives this module unwraps — nothing else.
    #[test]
    fn capture_file_names() {
        for yes in [
            "a.pcap",
            "a.pcapng",
            "a.cap",
            "A.PCAP",
            "a.pcap.gz",
            "a.pcapng.GZ",
            "s.tar",
            "s.tgz",
            "s.tar.gz",
            "s.TAR.GZ",
            #[cfg(feature = "archive")]
            "evidence.ZIP",
        ] {
            assert!(is_capture_file_name(yes), "{yes}");
        }
        for no in [
            "notes.txt",
            "x.gz",
            "notes.txt.gz",
            #[cfg(not(feature = "archive"))]
            "s.zip",
            "pcap",
            "",
            ".pcap",
            "s.tar.zst",
        ] {
            assert!(!is_capture_file_name(no), "{no}");
        }
    }

    #[test]
    fn container_format_recognizes_wrappers_and_passes_captures_through() {
        let tmp = tempfile::tempdir().expect("tmp");
        let cap = pcap_bytes(b"x");
        let plain = write(tmp.path(), "a.pcap", &cap);
        let gz = write(tmp.path(), "a.pcap.gz", &gzip(&cap));
        let tar = write(tmp.path(), "a.tar", &build(&[Spec::file("a.pcap", &cap)]));
        let empty = write(tmp.path(), "e.pcap", b"");
        assert_eq!(container_format(&plain).expect("plain"), None);
        assert_eq!(container_format(&empty).expect("empty"), None);
        assert_eq!(container_format(&gz).expect("gz"), Some(Format::Gzip));
        assert_eq!(container_format(&tar).expect("tar"), Some(Format::Tar));
    }

    /// The directory goes away with the expansion that owns it.
    #[test]
    fn dropping_the_expansion_deletes_the_extracted_files() {
        let tmp = tempfile::tempdir().expect("tmp");
        let tar = build(&[Spec::file("a.pcap", &pcap_bytes(b"x"))]);
        let path = write(tmp.path(), "a.tar", &tar);
        let exp = expand(&path, &limits()).expect("expand");
        let dir = exp.dir.as_ref().expect("dir").path().to_path_buf();
        assert!(dir.is_dir());
        drop(exp);
        assert!(!dir.exists(), "the extraction directory outlived its owner");
    }

    /// The sweep removes a directory whose owner is gone and leaves one whose
    /// owner still holds the lock.
    #[test]
    fn the_sweep_removes_only_abandoned_directories() {
        let root = tempfile::tempdir().expect("root");
        let alive = ExtractDir::create_in(root.path()).expect("alive");
        // An abandoned one: same shape, lock file present and unlocked.
        let dead = root.path().join(format!("{DIR_PREFIX}dead"));
        std::fs::create_dir(&dead).expect("mkdir");
        std::fs::write(dead.join(LOCK_NAME), b"").expect("lock");
        std::fs::write(dead.join("m00000.pcap"), b"left behind").expect("member");
        // Somebody else's name that merely looks similar is left alone.
        let other = root.path().join("sipnab-other");
        std::fs::create_dir(&other).expect("mkdir");

        let ours = ExtractDir::create_in(root.path()).expect("ours");
        assert!(!dead.exists(), "an abandoned extraction directory survived");
        assert!(alive.path().is_dir(), "a live one was removed");
        assert!(ours.path().is_dir());
        assert!(other.is_dir());
    }

    /// A symlink carrying our prefix is never followed into, whatever it
    /// points at.
    #[cfg(unix)]
    #[test]
    fn the_sweep_never_follows_a_planted_symlink() {
        let root = tempfile::tempdir().expect("root");
        let target = tempfile::tempdir().expect("target");
        std::fs::write(target.path().join(LOCK_NAME), b"").expect("lock");
        std::fs::write(target.path().join("precious"), b"keep").expect("file");
        let trap = root.path().join(format!("{DIR_PREFIX}trap"));
        std::os::unix::fs::symlink(target.path(), &trap).expect("symlink");
        let _ours = ExtractDir::create_in(root.path()).expect("ours");
        assert!(target.path().join("precious").exists());
        assert!(
            std::fs::symlink_metadata(&trap).is_ok(),
            "the planted link is not ours to delete either"
        );
    }
}
