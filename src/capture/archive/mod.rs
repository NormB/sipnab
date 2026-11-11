// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

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
#[cfg(feature = "archive")]
pub mod sevenz;
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
    /// A 7-Zip archive.
    SevenZip,
}

impl Layer {
    /// Short name for reports.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Gzip => "gzip",
            Self::Tar => "tar",
            Self::Zip => "zip",
            Self::SevenZip => "7z",
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
    /// 7-Zip's AES-256 with SHA-256 key derivation.
    SevenZipAes256,
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
            Self::SevenZipAes256 => "7z-aes-256",
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
    /// Opening it would cross a bound: which one.
    BoundExceeded(String),
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
            Self::BoundExceeded(which) => write!(
                f,
                "bound_exceeded ({which}): the archive asks for more work than sipnab allows \
                 an input, which is how a denial-of-service archive is built"
            ),
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
            Self::BoundExceeded(_) => "bound exceeded",
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
            Self::BoundExceeded(_) => "bound_exceeded",
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

/// Whether a parameter or argument NAME looks like it carries a password.
///
/// Case and separators are ignored, so `password`, `archive_password`,
/// `ArchivePassword` and `zip-passphrase` all match. The one rule behind the
/// REST surface's refusal of a password in a URL and the MCP surface's
/// refusal of a password in a tool call.
#[must_use]
pub fn is_password_like_name(name: &str) -> bool {
    let folded: String = name
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|c| c.to_ascii_lowercase())
        .collect();
    ["password", "passwd", "passphrase", "pwd"]
        .iter()
        .any(|w| folded.contains(w))
}

/// The fuzz entry point for the archive and password layer: the one body
/// both `fuzz/fuzz_targets/archive_password.rs` and the replay test in
/// `tests/archive_fuzz_replay_test.rs` drive.
///
/// `data` is a length byte, that many bytes of password, then an archive.
/// The archive is written to a private temporary file and walked with small
/// bounds and a keyring holding that one password, so every layer, every
/// encryption and the trial and rollback logic see hostile bytes. Whatever
/// happens is discarded: the contract is only that it returns.
#[doc(hidden)]
#[cfg(feature = "archive")]
pub fn fuzz_one_archive(data: &[u8]) {
    let Some((&n, rest)) = data.split_first() else {
        return;
    };
    let n = usize::from(n).min(rest.len());
    let (pw, archive) = rest.split_at(n);
    let Ok(mut file) = tempfile::NamedTempFile::new() else {
        return;
    };
    if io::Write::write_all(&mut file, archive).is_err() {
        return;
    }
    let candidates = password::ArchivePassword::from_bytes(pw)
        .map(|password| {
            vec![password::Candidate {
                password,
                source: password::Source::Request,
            }]
        })
        .unwrap_or_default();
    let mut keyring = password::Keyring::new(candidates, None);
    let limits = Limits {
        max_inflated_bytes: 1 << 20,
        max_entries: 64,
        max_depth: MAX_DEPTH,
    };
    let _ = expand_filtered_with(file.path(), &limits, None, Some(&mut keyring));
}

/// Whether this build unwraps `format` rather than handing it to libpcap or
/// naming it unsupported: gzip and tar always, ZIP with the `archive`
/// feature.
#[must_use]
pub fn unwraps(format: Format) -> bool {
    matches!(format, Format::Gzip | Format::Tar)
        || (matches!(format, Format::Zip | Format::SevenZip) && cfg!(feature = "archive"))
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
    container_format_in(&mut std::fs::File::open(path)?)
}

/// [`container_format`] for a file already open, read from where it stands.
///
/// # Errors
///
/// When the file cannot be read.
pub fn container_format_in(file: &mut dyn Read) -> io::Result<Option<Format>> {
    let mut head = [0u8; tar::BLOCK];
    let n = read_head(file, &mut head)?;
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
/// For listings only, through [`listed_kind`], where opening every file in a
/// directory to sniff it would be the wrong cost. Reading a file never consults this: [`sniff`] decides that.
#[must_use]
pub fn is_capture_file_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    if lower.ends_with(".tar") || lower.ends_with(".tgz") || lower.ends_with(".tar.gz") {
        // A bare ".tar" is a dotfile, not an archive of anything.
        return !matches!(lower.as_str(), ".tar" | ".tgz" | ".tar.gz");
    }
    if cfg!(feature = "archive") && (lower.ends_with(".zip") || lower.ends_with(".7z")) {
        return lower != ".zip" && lower != ".7z";
    }
    // Peel an optional `.gz` so `foo.pcap.gz` is judged by its `.pcap` stem.
    let stem = lower.strip_suffix(".gz").unwrap_or(lower.as_str());
    Path::new(stem)
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| matches!(e, "pcap" | "pcapng" | "cap"))
}

/// What a listing shows a file NAME as: a capture or an archive of captures
/// ([`is_capture_file_name`]), or a stored vCon container
/// ([`crate::capture::vcon_input::is_container_file_name`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListedKind {
    /// A pcap, pcapng or `.cap` file, compressed or not, or an archive of
    /// them.
    Capture,
    /// A stored vCon container, in any of its forms.
    Vcon,
}

impl ListedKind {
    /// The name a listing row carries: `capture` or `vcon`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Capture => "capture",
            Self::Vcon => "vcon",
        }
    }
}

/// Which kind of input a file NAME is listed as, or `None` for a name no
/// listing offers.
///
/// The one listing rule: the TUI's file browser, MCP `list_captures` and MCP
/// `find_in_captures` all list by it, so each offers every file
/// `open_capture` and `-I` read by name, stored vCon containers included.
/// Reading a file never consults it.
#[must_use]
pub fn listed_kind(name: &str) -> Option<ListedKind> {
    if is_capture_file_name(name) {
        Some(ListedKind::Capture)
    } else if crate::capture::vcon_input::is_container_file_name(name) {
        Some(ListedKind::Vcon)
    } else {
        None
    }
}

/// The files directly inside `dir` that [`listed_kind`] offers, with their
/// kind, sorted by path.
///
/// Regular files only, judged by `DirEntry::file_type`, which does not follow
/// a symbolic link: a link is skipped wherever it points. `Path::is_file`
/// follows it, so a link in an MCP file root to a capture outside the root
/// was listed by `list_captures` and read by `find_in_captures`. This matches
/// `vcon_analysis::report_directory`, which skips links the same way.
///
/// # Errors
///
/// When `dir` cannot be read.
pub fn listed_files(dir: &Path) -> std::io::Result<Vec<(PathBuf, ListedKind)>> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir)?.flatten() {
        let path = entry.path();
        let Some(kind) = path
            .file_name()
            .and_then(|n| n.to_str())
            .and_then(listed_kind)
        else {
            continue;
        };
        if !entry.file_type().is_ok_and(|t| t.is_file()) {
            continue;
        }
        out.push((path, kind));
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
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
        Format::Zip | Format::SevenZip => unwraps(Format::SevenZip),
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
        password::keyring_in_use(|keyring| expand_filtered_with(path, limits, keep, keyring))
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

/// [`expand`] for a file already open, read from where it stands, which goes
/// by `path`.
///
/// The `-I` reader of a run that drops privileges opens each file before the
/// drop and reads it through that descriptor, so `path` is never opened
/// again here: a ZIP or 7z at the top level, which [`expand`] reopens by path
/// to seek in, is copied into the extraction directory first instead.
///
/// # Errors
///
/// As [`expand`].
pub fn expand_opened(file: std::fs::File, path: &Path, limits: &Limits) -> io::Result<Expansion> {
    #[cfg(feature = "archive")]
    {
        password::keyring_in_use(|keyring| walk_opened(file, path, limits, keyring))
    }
    #[cfg(not(feature = "archive"))]
    {
        walk_opened(file, path, limits, ())
    }
}

/// [`expand_opened`], with the keyring given.
fn walk_opened(
    file: std::fs::File,
    path: &Path,
    limits: &Limits,
    keyring: KeyringArg<'_>,
) -> io::Result<Expansion> {
    let mut file = io::BufReader::new(file);
    let label = path.display().to_string();
    let mut walker = Walker::new(limits, None, path, &label);
    // Nothing reopens `path`: see `expand_opened`.
    walker.root = None;
    #[cfg(feature = "archive")]
    {
        walker.keyring = keyring;
    }
    #[cfg(not(feature = "archive"))]
    let () = keyring;
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
        password::keyring_in_use(|keyring| extract_member_with(path, label, limits, keyring))
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
    /// `entries`: what a failed trial met is not charged to the entry cap,
    /// or every wrong password would bring a 7z closer to it.
    entries: usize,
    /// `used`: the bytes a failed trial inflated are returned to the budget.
    ///
    /// The inflation ceiling bounds the output KEPT from one input, and a
    /// rolled-back trial keeps none: its files are deleted. Without this,
    /// several wrong passwords on a large archive reached the ceiling before
    /// the right one was tried (ARCHIVE-TRIAL-INFLATION-COUNT). The work
    /// stays bounded: each trial alone is still cut off at the ceiling, and
    /// the number of trials is the number of passwords given. A trial that
    /// itself reaches the ceiling is not rolled back. It is reported as
    /// [`Stop::InflationCap`] and ends the walk, because a member that large
    /// reaches the ceiling under the right password as well.
    used: u64,
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
            entries: self.entries,
            used: self.used.get(),
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

    /// Undo everything recorded since `mark`, deleting the files it wrote
    /// and returning the bytes inflated since then to the budget.
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
        self.entries = mark.entries;
        self.used.set(mark.used);
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
    ///
    /// A panic in a decoder, sipnab's or a dependency's, marks this stream
    /// broken and stops the walk of the stream holding it, instead of ending
    /// the process (PANIC-ABORT-HOSTILE-INPUT). Each member is its own scope,
    /// because the walk recurses; a panic inside a 7z decoder itself, outside
    /// any member, breaks that whole archive.
    fn walk(&mut self, src: &mut dyn Read, label: &str, layers: &[Layer], depth: usize) -> Flow {
        match crate::capture::contained("archive member", || {
            self.walk_inner(src, label, layers, depth)
        }) {
            Ok(flow) => flow,
            Err(message) => {
                let e = io::Error::other(format!("the decoder panicked: {message}"));
                self.broken(label, &e);
                Flow::Abort
            }
        }
    }

    /// [`Self::walk`] without the containment.
    fn walk_inner(
        &mut self,
        src: &mut dyn Read,
        label: &str,
        layers: &[Layer],
        depth: usize,
    ) -> Flow {
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
            Format::Zip | Format::SevenZip if depth >= self.limits.max_depth => {
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
            #[cfg(feature = "archive")]
            Format::SevenZip => self.walk_7z(&mut chained, label, layers, depth + 1),
            #[cfg(not(feature = "archive"))]
            Format::SevenZip => {
                self.skip(label, SkipReason::Unsupported(format));
                Flow::Continue
            }
            Format::Zstd | Format::Xz | Format::Bzip2 | Format::Lz4 => {
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

/// The name the lock file is created and locked under, before it is renamed to
/// [`LOCK_NAME`]. See [`ExtractDir::create_in_observed`].
const LOCK_STAGING_NAME: &str = ".owner.lock.new";

impl ExtractDir {
    /// Create a fresh directory under `root`, after removing any abandoned
    /// ones there.
    ///
    /// # Errors
    ///
    /// When the directory or its lock file cannot be created.
    pub fn create_in(root: &Path) -> io::Result<Self> {
        Self::create_in_observed(root, &mut |_| {})
    }

    /// [`Self::create_in`], calling `step` with the directory's path after
    /// each step that changes what a concurrent sweep would see.
    ///
    /// The seam exists for one test: a sweep run from inside `step` is a sweep
    /// that landed in that window, which is the only way to reproduce a race
    /// that is otherwise microseconds wide.
    fn create_in_observed(root: &Path, step: &mut dyn FnMut(&Path)) -> io::Result<Self> {
        let dir = tempfile::Builder::new()
            .prefix(DIR_PREFIX)
            .tempdir_in(root)?;
        step(dir.path());
        // Lock the file BEFORE it carries the name a sweep looks for. A sweep
        // that finds `LOCK_NAME` takes it as abandoned if it can lock it, so
        // the file must never be visible under that name unlocked. Until the
        // rename, a sweep sees a directory with no lock file, which it leaves
        // alone unless it is an hour old. The lock belongs to the open file,
        // not the name, so it survives the rename.
        let staging = dir.path().join(LOCK_STAGING_NAME);
        let lock = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&staging)?;
        step(dir.path());
        lock.try_lock().map_err(|e| match e {
            std::fs::TryLockError::Error(e) => e,
            std::fs::TryLockError::WouldBlock => {
                io::Error::other("a freshly created lock file is already locked")
            }
        })?;
        step(dir.path());
        std::fs::rename(&staging, dir.path().join(LOCK_NAME))?;
        step(dir.path());
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

/// What a run does with the directories it extracted archive members into,
/// before it chroots or drops privileges.
///
/// The extraction is made while the run still holds the credentials and the
/// root it started with: as root, a directory only root may enter (0700)
/// holding files only root may read (0600). The run then has to remove it
/// when it ends, as whoever it has become.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtractionHandover {
    /// Nothing changes: the run keeps its credentials and its root.
    Keep,
    /// Give every directory, and everything in it, to this user and group,
    /// which the run drops to: it can then still read the members by path
    /// and remove them at exit. The modes stay, so no other user can. A
    /// directory that user could not reach to remove (its `TMPDIR` lies
    /// inside a directory only another user may enter) is removed now
    /// instead, as for [`Self::Remove`].
    GiveTo {
        /// The user the run drops to.
        uid: u32,
        /// That user's primary group.
        gid: u32,
    },
    /// Remove every directory now. After a chroot no path reaches it, to read
    /// it or to remove it, so it goes while the run can still remove it. The
    /// run opens every member before it confines itself, and reads them
    /// through the descriptors it opened then.
    Remove,
}

/// What a run that `chroots`, and drops to the user and group `drop_to`
/// (`None` when it keeps its credentials), does with its extractions. Pure.
///
/// The chroot decides first: once it is made no path reaches the extraction,
/// whoever the run is.
#[must_use]
pub fn extraction_handover(chroots: bool, drop_to: Option<(u32, u32)>) -> ExtractionHandover {
    match (chroots, drop_to) {
        (true, _) => ExtractionHandover::Remove,
        (false, Some((uid, gid))) => ExtractionHandover::GiveTo { uid, gid },
        (false, None) => ExtractionHandover::Keep,
    }
}

/// Apply `handover` to every extraction this run holds
/// ([`keep_for_run`]). Call it while the run still has its credentials and
/// its root.
///
/// # Errors
///
/// The first change of owner that failed. Every extraction is still handed
/// over as far as it can be.
///
/// # Side effects
///
/// Changes the owner of, or removes, the run's extraction directories and
/// everything in them.
pub fn hand_over_run_extractions(handover: ExtractionHandover) -> io::Result<()> {
    let mut held = RUN.lock();
    match handover {
        ExtractionHandover::Keep => Ok(()),
        ExtractionHandover::Remove => {
            for kept in held.iter_mut() {
                kept.remove_from_disk();
            }
            Ok(())
        }
        ExtractionHandover::GiveTo { uid, gid } => {
            let mut first = None;
            for kept in held.iter_mut() {
                let Some(dir) = kept.dir().map(Path::to_path_buf) else {
                    continue;
                };
                if removable_as(&dir, uid, gid) {
                    if let Err(e) = give_tree_to(&dir, uid, gid, &mut change_owner) {
                        first.get_or_insert(e);
                    }
                } else {
                    kept.remove_from_disk();
                }
            }
            first.map_or(Ok(()), Err)
        }
    }
}

/// One directory on the path to an extraction: its permission bits and its
/// owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DirAccess {
    /// The mode, of which the low nine permission bits are read.
    mode: u32,
    /// The owning user.
    uid: u32,
    /// The owning group.
    gid: u32,
}

/// Whether a process running as `uid`, with primary group `gid`, can remove
/// an entry it owns from the last directory of `chain`, where `chain` lists
/// every directory from the root down. It needs search permission on each,
/// and write permission on the last. The class is the Unix one: the owner
/// bits when it owns the directory, else the group bits when its group does,
/// else the other bits. Pure.
///
/// Supplementary groups are not consulted, so this can answer `false` where
/// the process could remove the entry; the extraction is then removed before
/// the drop, as for a chroot. An empty chain answers `false`.
fn can_remove_entry_in(chain: &[DirAccess], uid: u32, gid: u32) -> bool {
    let bits = |d: &DirAccess| {
        let shift = if d.uid == uid {
            6
        } else if d.gid == gid {
            3
        } else {
            0
        };
        (d.mode >> shift) & 0o7
    };
    let Some(last) = chain.last() else {
        return false;
    };
    chain.iter().all(|d| bits(d) & 0o1 != 0) && bits(last) & 0o2 != 0
}

/// Whether the user and group a run drops to can remove the extraction
/// directory `dir` at exit once it owns it ([`can_remove_entry_in`] over the
/// directories that lead to it). `false` when they cannot be read.
#[cfg(unix)]
fn removable_as(dir: &Path, uid: u32, gid: u32) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    let Some(parent) = dir.parent() else {
        return false;
    };
    let Ok(parent) = std::fs::canonicalize(parent) else {
        return false;
    };
    let mut chain = Vec::new();
    for ancestor in parent.ancestors() {
        let Ok(meta) = std::fs::metadata(ancestor) else {
            return false;
        };
        chain.push(DirAccess {
            mode: meta.mode(),
            uid: meta.uid(),
            gid: meta.gid(),
        });
    }
    chain.reverse();
    can_remove_entry_in(&chain, uid, gid)
}

/// No owners to check where there are no uids.
#[cfg(not(unix))]
fn removable_as(_dir: &Path, _uid: u32, _gid: u32) -> bool {
    true
}

/// Change the owner of `path` itself, a link included, to `uid` and `gid`.
#[cfg(unix)]
fn change_owner(path: &Path, uid: u32, gid: u32) -> io::Result<()> {
    std::os::unix::fs::lchown(path, Some(uid), Some(gid))
}

/// No owners to change where there are no uids.
#[cfg(not(unix))]
fn change_owner(_path: &Path, _uid: u32, _gid: u32) -> io::Result<()> {
    Ok(())
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
    /// The directory itself. Dropped after the labels are withdrawn, or
    /// earlier by [`Self::remove_from_disk`].
    dir: Option<ExtractDir>,
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
            dir: Some(dir),
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

    /// The directory the members were extracted into, while it is on disk.
    #[must_use]
    pub fn dir(&self) -> Option<&Path> {
        self.dir.as_ref().map(ExtractDir::path)
    }

    /// Remove the directory and its members from disk now. The labels stay
    /// registered until this value drops, for the packets read from those
    /// members through descriptors opened before.
    pub fn remove_from_disk(&mut self) {
        drop(self.dir.take());
    }
}

/// Give `path`, and when it is a directory every entry under it, to `uid`
/// and `gid` through `chown`. A link is changed itself and never followed.
///
/// # Errors
///
/// The first `chown` that failed, or a directory that could not be listed.
fn give_tree_to(
    path: &Path,
    uid: u32,
    gid: u32,
    chown: &mut dyn FnMut(&Path, u32, u32) -> io::Result<()>,
) -> io::Result<()> {
    chown(path, uid, gid)?;
    if std::fs::symlink_metadata(path)?.is_dir() {
        for entry in std::fs::read_dir(path)? {
            give_tree_to(&entry?.path(), uid, gid, chown)?;
        }
    }
    Ok(())
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
    // A run stopped by SIGHUP exits 129 where it would have exited 0, so a
    // supervisor that restarts on failure restarts it (OPS-5).
    std::process::exit(crate::signals::exit_code(code))
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
        if let Some(dir) = kept.dir() {
            let _ = std::fs::remove_dir_all(dir);
        }
        // Its Drop would take the label lock; the directory is already gone,
        // and the process is about to be.
        std::mem::forget(kept);
    }
}

/// Directories holding this run's extracted members, for the path sandbox,
/// which must let the capture thread read them and let the run delete them.
#[must_use]
pub fn run_extraction_dirs() -> Vec<PathBuf> {
    RUN.lock()
        .iter()
        .filter_map(|k| k.dir().map(Path::to_path_buf))
        .collect()
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

    /// A run that chroots removes its extractions, whatever else it does; a
    /// run that only drops gives them to its user; a run that does neither
    /// keeps them.
    #[test]
    fn the_extraction_handover_follows_the_chroot_then_the_drop() {
        assert_eq!(
            extraction_handover(false, Some((65534, 65533))),
            ExtractionHandover::GiveTo {
                uid: 65534,
                gid: 65533
            },
            "a run that only drops gives its extractions to its user"
        );
        assert_eq!(
            extraction_handover(true, Some((65534, 65533))),
            ExtractionHandover::Remove,
            "a run that chroots and drops removes them"
        );
        assert_eq!(
            extraction_handover(true, None),
            ExtractionHandover::Remove,
            "a run that only chroots removes them"
        );
        assert_eq!(
            extraction_handover(false, None),
            ExtractionHandover::Keep,
            "a run that neither chroots nor drops keeps them"
        );
    }

    /// Giving an extraction away reaches the directory and every entry under
    /// it, and changes a link itself without following it.
    #[cfg(unix)]
    #[test]
    fn giving_an_extraction_away_reaches_every_entry_and_follows_no_link() -> Result<(), TestError>
    {
        let root = tempfile::tempdir()?;
        let dir = root.path().join("x");
        std::fs::create_dir_all(dir.join("sub"))?;
        std::fs::write(dir.join("m00000.pcap"), b"a")?;
        std::fs::write(dir.join("sub").join("z00001.zip"), b"b")?;
        let elsewhere = tempfile::tempdir()?;
        std::fs::write(elsewhere.path().join("not-ours"), b"c")?;
        std::os::unix::fs::symlink(elsewhere.path(), dir.join("link"))?;

        let mut seen = Vec::new();
        give_tree_to(&dir, 7, 8, &mut |p, uid, gid| {
            seen.push((p.to_path_buf(), uid, gid));
            Ok(())
        })?;
        seen.sort();
        let mut want: Vec<_> = [
            dir.clone(),
            dir.join("link"),
            dir.join("m00000.pcap"),
            dir.join("sub"),
            dir.join("sub").join("z00001.zip"),
        ]
        .into_iter()
        .map(|p| (p, 7, 8))
        .collect();
        want.sort();
        assert_eq!(
            seen, want,
            "every entry once, the link itself and not its target"
        );
        Ok(())
    }

    /// A change of owner that fails stops the handover with that error, so
    /// the run does not go on to drop with members it cannot remove.
    #[cfg(unix)]
    #[test]
    fn giving_an_extraction_away_stops_at_the_first_refused_entry() -> Result<(), TestError> {
        let root = tempfile::tempdir()?;
        let dir = root.path().join("x");
        std::fs::create_dir_all(&dir)?;
        std::fs::write(dir.join("m00000.pcap"), b"a")?;
        let mut calls = 0usize;
        let err = give_tree_to(&dir, 7, 8, &mut |p, _, _| {
            calls += 1;
            if p.ends_with("m00000.pcap") {
                Err(io::Error::from(io::ErrorKind::PermissionDenied))
            } else {
                Ok(())
            }
        })
        .err()
        .ok_or("a refused change of owner must fail the handover")?;
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied, "{err}");
        assert_eq!(calls, 2, "the directory, then the member that failed");
        Ok(())
    }

    /// Giving away a path that is not there fails with `NotFound` after the
    /// change of owner, and asks for no other entry.
    #[cfg(unix)]
    #[test]
    fn giving_away_a_missing_extraction_fails() -> Result<(), TestError> {
        let root = tempfile::tempdir()?;
        let gone = root.path().join("gone");
        let mut calls = 0usize;
        let err = give_tree_to(&gone, 7, 8, &mut |_, _, _| {
            calls += 1;
            Ok(())
        })
        .err()
        .ok_or("a missing extraction must fail the handover")?;
        assert_eq!(err.kind(), io::ErrorKind::NotFound, "{err}");
        assert_eq!(calls, 1, "{err}");
        Ok(())
    }

    /// The directory chain to an extraction, from the root down, for
    /// [`can_remove_entry_in`]: `(mode, owner uid, owner gid)` each.
    fn chain(dirs: &[(u32, u32, u32)]) -> Vec<DirAccess> {
        dirs.iter()
            .map(|&(mode, uid, gid)| DirAccess { mode, uid, gid })
            .collect()
    }

    /// `/` and `/tmp` as Linux has them: anyone may search both and write
    /// `/tmp`, so the drop user can remove what it owns there.
    #[test]
    fn a_drop_user_can_remove_its_extraction_from_tmp() {
        let tmp = chain(&[(0o755, 0, 0), (0o1777, 0, 0)]);
        assert!(can_remove_entry_in(&tmp, 65534, 65534), "/tmp is reachable");
    }

    /// A directory the drop user owns is judged by its owner bits.
    #[test]
    fn the_owner_bits_decide_for_a_directory_the_drop_user_owns() {
        let own = chain(&[(0o755, 0, 0), (0o700, 65534, 0)]);
        assert!(
            can_remove_entry_in(&own, 65534, 65534),
            "its own 0700 directory"
        );
    }

    /// A `TMPDIR` inside another user's 0700 directory, as root's macOS
    /// directory under `/var/folders` is, cannot be reached, however open the
    /// `TMPDIR` itself is.
    #[test]
    fn a_tmpdir_inside_another_users_private_directory_is_out_of_reach() {
        let macos = chain(&[(0o755, 0, 0), (0o700, 501, 20), (0o1777, 501, 20)]);
        assert!(
            !can_remove_entry_in(&macos, 65534, 65534),
            "nobody cannot search the 0700 directory on the way"
        );
    }

    /// A directory the drop user may search but not write keeps the entry.
    #[test]
    fn a_parent_the_drop_user_cannot_write_is_out_of_reach() {
        let read_only = chain(&[(0o755, 0, 0), (0o755, 0, 0)]);
        assert!(
            !can_remove_entry_in(&read_only, 65534, 65534),
            "no write permission on the parent"
        );
    }

    /// The group class applies when the group matches, even where the other
    /// bits would allow more: Unix asks one class, not the best one.
    #[test]
    fn the_group_class_is_asked_before_the_other_bits() {
        let group_ok = chain(&[(0o755, 0, 0), (0o070, 0, 65534)]);
        assert!(can_remove_entry_in(&group_ok, 65534, 65534), "group rwx");
        let group_shut = chain(&[(0o755, 0, 0), (0o707, 0, 65534)]);
        assert!(
            !can_remove_entry_in(&group_shut, 65534, 65534),
            "the group bits are empty, so the other bits do not count"
        );
    }

    /// No directories means nothing to reach.
    #[test]
    fn an_empty_chain_is_out_of_reach() {
        assert!(
            !can_remove_entry_in(&[], 65534, 65534),
            "no chain, no answer"
        );
    }

    /// A descriptor whose read fails is answered with that error, not taken
    /// for a file that is not an archive.
    #[test]
    fn the_format_of_an_unreadable_descriptor_is_an_error() {
        struct Broken;
        impl Read for Broken {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::from(io::ErrorKind::BrokenPipe))
            }
        }
        let err = container_format_in(&mut Broken).err();
        assert_eq!(
            err.map(|e| e.kind()),
            Some(io::ErrorKind::BrokenPipe),
            "the read error must be the answer"
        );
    }

    /// An empty descriptor is no archive.
    #[test]
    fn an_empty_descriptor_is_no_archive() -> Result<(), TestError> {
        assert_eq!(
            container_format_in(&mut io::empty())?,
            None,
            "no bytes, no archive format"
        );
        Ok(())
    }

    /// Removing an extraction from disk removes its directory and keeps its
    /// labels, which name the packets already read from its members.
    #[test]
    fn removing_an_extraction_from_disk_keeps_its_labels() -> Result<(), TestError> {
        let root = tempfile::tempdir()?;
        let dir = ExtractDir::create_in(root.path())?;
        let on_disk = dir.path().to_path_buf();
        let member = on_disk.join("m00000.pcap");
        std::fs::write(&member, b"a")?;
        let mut kept =
            KeptExtraction::new(dir, vec![(member.clone(), "set.tar/a.pcap".to_string())]);
        kept.remove_from_disk();
        assert!(!on_disk.exists(), "the directory is gone");
        assert_eq!(kept.dir(), None, "nothing is on disk to report");
        assert_eq!(
            source_name(&member),
            "set.tar/a.pcap",
            "the label outlives the directory"
        );
        drop(kept);
        assert_eq!(
            source_name(&member),
            member.display().to_string(),
            "the label goes when the extraction drops"
        );
        Ok(())
    }

    /// Any error a test can return; `?` converts into it.
    type TestError = Box<dyn std::error::Error>;

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

    fn gzip(data: &[u8]) -> Result<Vec<u8>, TestError> {
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(data).map_err(|e| format!("gzip: {e:?}"))?;
        Ok(enc.finish().map_err(|e| format!("gzip: {e:?}"))?)
    }

    fn limits() -> Limits {
        Limits {
            max_inflated_bytes: 64 * 1024 * 1024,
            max_entries: MAX_ENTRIES,
            max_depth: MAX_DEPTH,
        }
    }

    fn write(dir: &Path, name: &str, bytes: &[u8]) -> Result<PathBuf, TestError> {
        let p = dir.join(name);
        std::fs::write(&p, bytes).map_err(|e| format!("write: {e:?}"))?;
        Ok(p)
    }

    fn labels(exp: &Expansion) -> Vec<String> {
        exp.members.iter().map(|m| m.label.clone()).collect()
    }

    #[test]
    fn sniff_names_every_format_by_its_magic() -> Result<(), TestError> {
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
        Ok(())
    }

    /// The whole reason this module exists: the members of a `.tgz` come out
    /// as captures, with labels naming the archive and the member.
    #[test]
    fn a_tgz_of_captures_expands_to_its_members() -> Result<(), TestError> {
        let tmp = tempfile::tempdir().map_err(|e| format!("tmp: {e:?}"))?;
        let a = pcap_bytes(b"alpha");
        let b = pcap_bytes(b"bravo");
        let tar = build(&[
            Spec::dir("set/"),
            Spec::file("set/a.pcap", &a),
            Spec::file("set/b.pcap", &b),
        ]);
        let tgz = write(tmp.path(), "set.tgz", &gzip(&tar)?)?;
        let exp = expand(&tgz, &limits()).map_err(|e| format!("expand: {e:?}"))?;
        let root = tgz.display().to_string();
        assert_eq!(
            labels(&exp),
            vec![format!("{root}/set/a.pcap"), format!("{root}/set/b.pcap")]
        );
        assert_eq!(exp.directories, 1);
        assert!(exp.skipped.is_empty(), "{:?}", exp.skipped);
        assert!(exp.stops.is_empty(), "{:?}", exp.stops);
        assert_eq!(exp.members[0].layers, vec![Layer::Gzip, Layer::Tar]);
        assert_eq!(
            std::fs::read(&exp.members[0].path).map_err(|e| format!("read: {e:?}"))?,
            a
        );
        assert_eq!(
            std::fs::read(&exp.members[1].path).map_err(|e| format!("read: {e:?}"))?,
            b
        );
        Ok(())
    }

    /// Plain `.tar`, and a `.pcap.gz` that is merely compressed, go through
    /// the same walk.
    #[test]
    fn a_plain_tar_and_a_single_gzip_use_the_same_walk() -> Result<(), TestError> {
        let tmp = tempfile::tempdir().map_err(|e| format!("tmp: {e:?}"))?;
        let cap = pcap_bytes(b"x");
        let tar = write(tmp.path(), "set.tar", &build(&[Spec::file("x.pcap", &cap)]))?;
        let exp = expand(&tar, &limits()).map_err(|e| format!("tar: {e:?}"))?;
        assert_eq!(labels(&exp), vec![format!("{}/x.pcap", tar.display())]);
        assert_eq!(exp.members[0].layers, vec![Layer::Tar]);

        let gz = write(tmp.path(), "one.pcap.gz", &gzip(&cap)?)?;
        let exp = expand(&gz, &limits()).map_err(|e| format!("gz: {e:?}"))?;
        assert_eq!(
            labels(&exp),
            vec![gz.display().to_string()],
            "a compressed capture keeps its own name: there is no member to name"
        );
        assert_eq!(exp.members[0].layers, vec![Layer::Gzip]);
        assert_eq!(
            std::fs::read(&exp.members[0].path).map_err(|e| format!("read: {e:?}"))?,
            cap
        );
        Ok(())
    }

    /// Every member that is not a capture is accounted for with its reason,
    /// and none of them stops the rest being read.
    #[test]
    fn every_non_capture_member_is_skipped_with_its_reason() -> Result<(), TestError> {
        let tmp = tempfile::tempdir().map_err(|e| format!("tmp: {e:?}"))?;
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
        let path = write(tmp.path(), "mixed.tar", &tar)?;
        let exp = expand(&path, &limits()).map_err(|e| format!("expand: {e:?}"))?;
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
        Ok(())
    }

    /// A trial that fails takes back everything it recorded: the members it
    /// wrote, their files, its skips and stops, and the labels it claimed.
    #[test]
    fn a_rolled_back_trial_leaves_nothing_behind() -> Result<(), TestError> {
        let tmp = tempfile::tempdir().map_err(|e| format!("tmp: {e:?}"))?;
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
        Ok(())
    }

    /// FAILURE (ARCHIVE-TRIAL-INFLATION-COUNT): a trial that fails also gives
    /// back the bytes it inflated. Its output is deleted, and the ceiling
    /// bounds the output kept. The bytes inflated before the trial stay
    /// counted.
    #[test]
    fn a_rolled_back_trial_returns_its_inflated_bytes() -> Result<(), TestError> {
        let tmp = tempfile::tempdir().map_err(|e| format!("tmp: {e:?}"))?;
        let root = tmp.path().join("r");
        let lim = Limits {
            max_inflated_bytes: 4096,
            ..limits()
        };
        let mut w = Walker::new(&lim, None, &root, "r");
        let kept = pcap_bytes(&[1u8; 100]);
        let mut first = Inflating {
            inner: &kept[..],
            used: std::rc::Rc::clone(&w.used),
            limit: lim.max_inflated_bytes,
        };
        assert_eq!(
            w.walk(&mut first, "r/kept", &[], 1),
            Flow::Continue,
            "a capture read outside a trial"
        );
        let before = w.used.get();
        assert_eq!(before, kept.len() as u64, "the kept member is counted");

        let mark = w.checkpoint();
        w.trial = true;
        let noise = [0x77u8; 3000];
        let mut second = Inflating {
            inner: &noise[..],
            used: std::rc::Rc::clone(&w.used),
            limit: lim.max_inflated_bytes,
        };
        let _ = w.walk(&mut second, "r/noise", &[], 1);
        w.trial = false;
        assert_eq!(
            w.used.get(),
            before + noise.len() as u64,
            "the trial's bytes are counted while it runs"
        );
        w.rollback(mark);
        assert_eq!(
            w.used.get(),
            before,
            "the rollback returns the trial's bytes and keeps the earlier ones"
        );
        Ok(())
    }

    /// EDGE: a rollback to a checkpoint taken before anything was inflated
    /// returns the count to zero, and a rollback with no trial bytes changes
    /// nothing.
    #[test]
    fn a_rollback_restores_the_count_of_its_own_checkpoint() -> Result<(), TestError> {
        let tmp = tempfile::tempdir().map_err(|e| format!("tmp: {e:?}"))?;
        let root = tmp.path().join("r");
        let lim = limits();
        let mut w = Walker::new(&lim, None, &root, "r");
        let empty = w.checkpoint();
        w.used.set(700);
        let later = w.checkpoint();
        w.rollback(later);
        assert_eq!(w.used.get(), 700, "nothing was inflated since this mark");
        w.used.set(900);
        w.rollback(empty);
        assert_eq!(w.used.get(), 0, "the first mark was taken at zero");
        Ok(())
    }

    /// On trial, a member whose stream fails in any way is the password's
    /// fault: the trial is rejected and nothing is recorded, rather than the
    /// whole walk ending on a write failure.
    #[test]
    fn a_stream_failure_on_trial_rejects_rather_than_stops() -> Result<(), TestError> {
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
        let tmp = tempfile::tempdir().map_err(|e| format!("tmp: {e:?}"))?;
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
        Ok(())
    }

    /// PANIC-ABORT-HOSTILE-INPUT: a decoder that panics while a member is
    /// read marks that stream broken and stops its walk, and the process goes
    /// on. The panic comes from the reader, because no real archive is known
    /// to make a decoder panic.
    #[cfg(feature = "native")]
    #[test]
    fn a_member_whose_reader_panics_is_broken_not_fatal() -> Result<(), TestError> {
        struct Panicking;
        impl Read for Panicking {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                panic!("hostile member probe")
            }
        }
        let tmp = tempfile::tempdir().map_err(|e| format!("tmp: {e:?}"))?;
        let root = tmp.path().join("r");
        let lim = limits();
        let before = crate::crash::contained_panics();
        let mut w = Walker::new(&lim, None, &root, "r");
        assert_eq!(w.walk(&mut Panicking, "r/m", &[], 0), Flow::Abort);
        let detail = match w.out.stops.as_slice() {
            [Stop::Broken { container, detail }] if container == "r/m" => detail.clone(),
            other => return Err(format!("expected one Broken stop for r/m: {other:?}").into()),
        };
        assert!(
            detail.contains("the decoder panicked: hostile member probe"),
            "{detail}"
        );
        assert!(
            crate::crash::contained_panics() > before,
            "the panic is counted"
        );
        Ok(())
    }

    /// Two layers of compression and archiving inside each other: a
    /// `.pcap.gz` member of a tar inside a `.tgz`.
    #[test]
    fn nested_layers_are_unwrapped_and_labeled_by_their_path() -> Result<(), TestError> {
        let tmp = tempfile::tempdir().map_err(|e| format!("tmp: {e:?}"))?;
        let cap = pcap_bytes(b"deep");
        let inner = build(&[Spec::file("ring/x.pcap.gz", &gzip(&cap)?)]);
        let outer = build(&[Spec::file("inner.tar", &inner)]);
        let path = write(tmp.path(), "outer.tgz", &gzip(&outer)?)?;
        let exp = expand(&path, &limits()).map_err(|e| format!("expand: {e:?}"))?;
        assert_eq!(
            labels(&exp),
            vec![format!("{}/inner.tar/ring/x.pcap.gz", path.display())]
        );
        assert_eq!(
            exp.members[0].layers,
            vec![Layer::Gzip, Layer::Tar, Layer::Tar, Layer::Gzip]
        );
        assert_eq!(
            std::fs::read(&exp.members[0].path).map_err(|e| format!("read: {e:?}"))?,
            cap
        );
        Ok(())
    }

    /// A member named to climb out of the extraction directory lands inside
    /// it, under a name this module chose, and nothing is written anywhere
    /// else.
    #[test]
    fn a_member_name_never_becomes_a_path() -> Result<(), TestError> {
        let tmp = tempfile::tempdir().map_err(|e| format!("tmp: {e:?}"))?;
        let victim_dir = tmp.path().join("victim");
        std::fs::create_dir(&victim_dir).map_err(|e| format!("mkdir: {e:?}"))?;
        let cap = pcap_bytes(b"x");
        let evil = format!("../../../../{}/owned.pcap", victim_dir.display());
        let tar = build(&[Spec::file(&evil, &cap), Spec::file("/etc/abs.pcap", &cap)]);
        let path = write(tmp.path(), "evil.tar", &tar)?;
        let exp = expand(&path, &limits()).map_err(|e| format!("expand: {e:?}"))?;
        assert_eq!(exp.members.len(), 2);
        let dir = exp.dir.as_ref().ok_or("dir")?.path().to_path_buf();
        for m in &exp.members {
            assert_eq!(m.path.parent(), Some(dir.as_path()), "{m:?}");
            let file = m.path.file_name().and_then(|n| n.to_str()).ok_or("name")?;
            assert!(file.starts_with('m') && !file.contains("owned"), "{file}");
        }
        assert_eq!(
            std::fs::read_dir(&victim_dir)
                .map_err(|e| format!("ls: {e:?}"))?
                .count(),
            0,
            "nothing written outside the extraction directory"
        );
        Ok(())
    }

    /// A gzip bomb is refused having written no more than the ceiling, and the
    /// refusal says where and why.
    #[test]
    fn a_decompression_bomb_stops_at_the_ceiling() -> Result<(), TestError> {
        let tmp = tempfile::tempdir().map_err(|e| format!("tmp: {e:?}"))?;
        // A pcap header followed by 8 MiB of zeros compresses to ~8 KiB.
        let mut big = pcap_bytes(b"");
        big.resize(8 * 1024 * 1024, 0);
        let path = write(tmp.path(), "bomb.pcap.gz", &gzip(&gzip(&big)?)?)?;
        let tight = Limits {
            max_inflated_bytes: 1024 * 1024,
            ..limits()
        };
        let exp = expand(&path, &tight).map_err(|e| format!("expand: {e:?}"))?;
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
            .map(|d| -> Result<u64, String> {
                Ok(std::fs::read_dir(d.path())
                    .map_err(|e| format!("ls: {e:?}"))?
                    .filter_map(Result::ok)
                    .filter_map(|e| e.metadata().ok())
                    .map(|m| m.len())
                    .sum())
            })
            .transpose()?
            .unwrap_or(0);
        assert!(
            written <= 1024 * 1024,
            "wrote {written} bytes past the ceiling"
        );
        Ok(())
    }

    #[test]
    fn nesting_past_the_depth_limit_is_refused() -> Result<(), TestError> {
        let tmp = tempfile::tempdir().map_err(|e| format!("tmp: {e:?}"))?;
        let mut data = pcap_bytes(b"x");
        for _ in 0..(MAX_DEPTH + 1) {
            data = gzip(&data)?;
        }
        let path = write(tmp.path(), "deep.gz", &data)?;
        let exp = expand(&path, &limits()).map_err(|e| format!("expand: {e:?}"))?;
        assert!(exp.members.is_empty());
        assert_eq!(exp.skipped.len(), 1);
        assert_eq!(exp.skipped[0].reason, SkipReason::TooDeep);
        Ok(())
    }

    #[test]
    fn the_entry_cap_stops_the_walk_and_says_so() -> Result<(), TestError> {
        let tmp = tempfile::tempdir().map_err(|e| format!("tmp: {e:?}"))?;
        let cap = pcap_bytes(b"x");
        let names: Vec<String> = (0..5).map(|i| format!("{i}.pcap")).collect();
        let specs: Vec<Spec<'_>> = names.iter().map(|n| Spec::file(n, &cap)).collect();
        let path = write(tmp.path(), "many.tar", &build(&specs))?;
        let few = Limits {
            max_entries: 3,
            ..limits()
        };
        let exp = expand(&path, &few).map_err(|e| format!("expand: {e:?}"))?;
        assert_eq!(exp.members.len(), 3);
        assert_eq!(exp.stops, vec![Stop::EntryCap { limit: 3 }]);
        Ok(())
    }

    /// A truncated archive keeps what arrived, marks the member it broke off
    /// inside, and records that the walk ended there.
    #[test]
    fn a_truncated_archive_keeps_what_arrived() -> Result<(), TestError> {
        let tmp = tempfile::tempdir().map_err(|e| format!("tmp: {e:?}"))?;
        let a = pcap_bytes(b"whole");
        let mut b = pcap_bytes(b"");
        b.resize(3000, 0xab);
        let tar = build(&[Spec::file("a.pcap", &a), Spec::file("b.pcap", &b)]);
        // Cut inside b's data: header(512) + a(512) + b header(512) + 1000.
        let path = write(tmp.path(), "cut.tar", &tar[..512 * 3 + 1000])?;
        let exp = expand(&path, &limits()).map_err(|e| format!("expand: {e:?}"))?;
        assert_eq!(exp.members.len(), 2);
        assert!(exp.members[0].cut_short.is_none());
        assert!(exp.members[1].cut_short.is_some(), "{:?}", exp.members[1]);
        assert_eq!(
            std::fs::metadata(&exp.members[1].path)
                .map_err(|e| format!("meta: {e:?}"))?
                .len(),
            1000
        );
        assert!(exp.lossy());
        Ok(())
    }

    /// A member cut off inside its FIRST block still keeps what arrived. The
    /// walk reads a block to identify a stream, and that read hitting the cut
    /// used to discard the member as though it were never there.
    #[test]
    fn a_member_cut_inside_its_first_block_is_still_kept() -> Result<(), TestError> {
        let tmp = tempfile::tempdir().map_err(|e| format!("tmp: {e:?}"))?;
        let a = pcap_bytes(b"whole");
        let mut b = pcap_bytes(b"");
        b.resize(3000, 0xab);
        let tar = build(&[Spec::file("a.pcap", &a), Spec::file("b.pcap", &b)]);
        let path = write(tmp.path(), "cut.tgz", &gzip(&tar[..512 * 3 + 100])?)?;
        let exp = expand(&path, &limits()).map_err(|e| format!("expand: {e:?}"))?;
        assert_eq!(exp.members.len(), 2, "{exp:?}");
        assert!(exp.members[1].cut_short.is_some(), "{:?}", exp.members[1]);
        assert_eq!(
            std::fs::metadata(&exp.members[1].path)
                .map_err(|e| format!("meta: {e:?}"))?
                .len(),
            100
        );
        Ok(())
    }

    #[test]
    fn a_corrupt_header_ends_the_walk_but_keeps_earlier_members() -> Result<(), TestError> {
        let tmp = tempfile::tempdir().map_err(|e| format!("tmp: {e:?}"))?;
        let cap = pcap_bytes(b"x");
        let mut tar = build(&[Spec::file("a.pcap", &cap), Spec::file("b.pcap", &cap)]);
        tar[1024 + 3] ^= 0x55;
        let path = write(tmp.path(), "bent.tar", &tar)?;
        let exp = expand(&path, &limits()).map_err(|e| format!("expand: {e:?}"))?;
        assert_eq!(exp.members.len(), 1);
        assert!(
            matches!(&exp.stops[..], [Stop::Broken { .. }]),
            "{:?}",
            exp.stops
        );
        Ok(())
    }

    #[test]
    fn a_repeated_member_name_is_read_once() -> Result<(), TestError> {
        let tmp = tempfile::tempdir().map_err(|e| format!("tmp: {e:?}"))?;
        let first = pcap_bytes(b"first");
        let second = pcap_bytes(b"second");
        let tar = build(&[Spec::file("x.pcap", &first), Spec::file("x.pcap", &second)]);
        let path = write(tmp.path(), "dup.tar", &tar)?;
        let exp = expand(&path, &limits()).map_err(|e| format!("expand: {e:?}"))?;
        assert_eq!(exp.members.len(), 1);
        assert_eq!(
            std::fs::read(&exp.members[0].path).map_err(|e| format!("read: {e:?}"))?,
            first
        );
        assert_eq!(exp.skipped[0].reason, SkipReason::DuplicateName);
        Ok(())
    }

    /// Following a pointer extracts exactly the member it names, through
    /// every layer, and nothing else.
    #[test]
    fn extract_member_finds_the_member_a_label_names() -> Result<(), TestError> {
        let tmp = tempfile::tempdir().map_err(|e| format!("tmp: {e:?}"))?;
        let a = pcap_bytes(b"alpha");
        let b = pcap_bytes(b"bravo");
        let inner = build(&[Spec::file("b.pcap.gz", &gzip(&b)?)]);
        let outer = build(&[Spec::file("a.pcap", &a), Spec::file("in.tar", &inner)]);
        let path = write(tmp.path(), "o.tgz", &gzip(&outer)?)?;
        let root = path.display().to_string();

        let (m, dir) = extract_member(&path, &format!("{root}/in.tar/b.pcap.gz"), &limits())
            .map_err(|e| format!("walk: {e:?}"))?
            .ok_or("found")?;
        assert_eq!(
            std::fs::read(&m.path).map_err(|e| format!("read: {e:?}"))?,
            b
        );
        assert_eq!(
            std::fs::read_dir(dir.path())
                .map_err(|e| format!("ls: {e:?}"))?
                .filter_map(Result::ok)
                .filter(|e| e.file_name() != LOCK_NAME)
                .count(),
            1,
            "only the named member is written"
        );
        assert!(
            extract_member(&path, &format!("{root}/nope.pcap"), &limits())
                .map_err(|e| format!("walk: {e:?}"))?
                .is_none()
        );
        Ok(())
    }

    /// The names a file browser and MCP `list_captures` offer: captures,
    /// compressed captures, and archives this module unwraps — nothing else.
    #[test]
    fn capture_file_names() -> Result<(), TestError> {
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
        Ok(())
    }

    /// The listing rule names a capture as a capture and a stored vCon
    /// container, gzip format included, as a vCon. A spool's
    /// `.<name>.partial` temp file, other JSON and a bare suffix are not
    /// listed.
    #[test]
    fn listed_kinds() {
        for (name, want) in [
            ("a.pcap", Some(ListedKind::Capture)),
            ("s.tgz", Some(ListedKind::Capture)),
            ("call.vcon.json", Some(ListedKind::Vcon)),
            ("CALL.VCON.JSON", Some(ListedKind::Vcon)),
            ("call.vcon.json.gz", Some(ListedKind::Vcon)),
            (".call.vcon.json.partial", None),
            ("notes.json", None),
            (".vcon.json", None),
            (".vcon.json.gz", None),
            ("call.vcon.json.error.json", None),
        ] {
            assert_eq!(listed_kind(name), want, "{name}");
        }
    }

    #[test]
    fn container_format_recognizes_wrappers_and_passes_captures_through() -> Result<(), TestError> {
        let tmp = tempfile::tempdir().map_err(|e| format!("tmp: {e:?}"))?;
        let cap = pcap_bytes(b"x");
        let plain = write(tmp.path(), "a.pcap", &cap)?;
        let gz = write(tmp.path(), "a.pcap.gz", &gzip(&cap)?)?;
        let tar = write(tmp.path(), "a.tar", &build(&[Spec::file("a.pcap", &cap)]))?;
        let empty = write(tmp.path(), "e.pcap", b"")?;
        assert_eq!(
            container_format(&plain).map_err(|e| format!("plain: {e:?}"))?,
            None
        );
        assert_eq!(
            container_format(&empty).map_err(|e| format!("empty: {e:?}"))?,
            None
        );
        assert_eq!(
            container_format(&gz).map_err(|e| format!("gz: {e:?}"))?,
            Some(Format::Gzip)
        );
        assert_eq!(
            container_format(&tar).map_err(|e| format!("tar: {e:?}"))?,
            Some(Format::Tar)
        );
        Ok(())
    }

    /// The directory goes away with the expansion that owns it.
    #[test]
    fn dropping_the_expansion_deletes_the_extracted_files() -> Result<(), TestError> {
        let tmp = tempfile::tempdir().map_err(|e| format!("tmp: {e:?}"))?;
        let tar = build(&[Spec::file("a.pcap", &pcap_bytes(b"x"))]);
        let path = write(tmp.path(), "a.tar", &tar)?;
        let exp = expand(&path, &limits()).map_err(|e| format!("expand: {e:?}"))?;
        let dir = exp.dir.as_ref().ok_or("dir")?.path().to_path_buf();
        assert!(dir.is_dir());
        drop(exp);
        assert!(!dir.exists(), "the extraction directory outlived its owner");
        Ok(())
    }

    /// The sweep removes a directory whose owner is gone and leaves one whose
    /// owner still holds the lock.
    #[test]
    fn the_sweep_removes_only_abandoned_directories() -> Result<(), TestError> {
        let root = tempfile::tempdir().map_err(|e| format!("root: {e:?}"))?;
        let alive = ExtractDir::create_in(root.path()).map_err(|e| format!("alive: {e:?}"))?;
        // An abandoned one: same shape, lock file present and unlocked.
        let dead = root.path().join(format!("{DIR_PREFIX}dead"));
        std::fs::create_dir(&dead).map_err(|e| format!("mkdir: {e:?}"))?;
        std::fs::write(dead.join(LOCK_NAME), b"").map_err(|e| format!("lock: {e:?}"))?;
        std::fs::write(dead.join("m00000.pcap"), b"left behind")
            .map_err(|e| format!("member: {e:?}"))?;
        // Somebody else's name that merely looks similar is left alone.
        let other = root.path().join("sipnab-other");
        std::fs::create_dir(&other).map_err(|e| format!("mkdir: {e:?}"))?;

        let ours = ExtractDir::create_in(root.path()).map_err(|e| format!("ours: {e:?}"))?;
        assert!(!dead.exists(), "an abandoned extraction directory survived");
        assert!(alive.path().is_dir(), "a live one was removed");
        assert!(ours.path().is_dir());
        assert!(other.is_dir());
        Ok(())
    }

    /// A sweep that lands while a directory is still being created leaves it
    /// alone, at every step of the creation.
    ///
    /// The lock file used to be created under its final name and locked a
    /// moment later. A sweep in that gap found the lock takeable and removed a
    /// live directory, and the walk that owned it then failed to write its
    /// first member and returned none. It surfaced as
    /// `a_truncated_archive_keeps_what_arrived` finding 0 members on macOS CI,
    /// where parallel tests share the system temp directory and sweep it.
    #[test]
    fn a_sweep_inside_creation_never_removes_the_directory_being_made() -> Result<(), TestError> {
        let root = tempfile::tempdir().map_err(|e| format!("root: {e:?}"))?;
        // The sweeper needs a real directory of its own to compare owners with.
        let sweeper = root.path().join("sweeper");
        std::fs::create_dir(&sweeper).map_err(|e| format!("mkdir: {e:?}"))?;
        let mut steps = 0;
        let made = ExtractDir::create_in_observed(root.path(), &mut |dir| {
            steps += 1;
            let removed = sweep_abandoned(root.path(), &sweeper);
            assert!(
                dir.is_dir() && removed == 0,
                "a sweep at creation step {steps} removed the directory being made"
            );
        })
        .map_err(|e| format!("create: {e:?}"))?;
        assert!(steps >= 3, "only {steps} step(s) observed");
        assert!(made.path().join(LOCK_NAME).exists());
        std::fs::write(made.path().join("m00000.pcap"), b"x")
            .map_err(|e| format!("still writable: {e:?}"))?;
        Ok(())
    }

    /// A symlink carrying our prefix is never followed into, whatever it
    /// points at.
    #[cfg(unix)]
    #[test]
    fn the_sweep_never_follows_a_planted_symlink() -> Result<(), TestError> {
        let root = tempfile::tempdir().map_err(|e| format!("root: {e:?}"))?;
        let target = tempfile::tempdir().map_err(|e| format!("target: {e:?}"))?;
        std::fs::write(target.path().join(LOCK_NAME), b"").map_err(|e| format!("lock: {e:?}"))?;
        std::fs::write(target.path().join("precious"), b"keep")
            .map_err(|e| format!("file: {e:?}"))?;
        let trap = root.path().join(format!("{DIR_PREFIX}trap"));
        std::os::unix::fs::symlink(target.path(), &trap).map_err(|e| format!("symlink: {e:?}"))?;
        let _ours = ExtractDir::create_in(root.path()).map_err(|e| format!("ours: {e:?}"))?;
        assert!(target.path().join("precious").exists());
        assert!(
            std::fs::symlink_metadata(&trap).is_ok(),
            "the planted link is not ours to delete either"
        );
        Ok(())
    }

    /// MCP-SWEEP-FOLLOWS-SYMLINKS: a symbolic link in the root is never
    /// offered, wherever it points. `is_file` follows the link, so a link to
    /// a capture outside the root was listed and read.
    #[cfg(unix)]
    #[test]
    fn listed_files_skips_links_directories_and_other_files()
    -> Result<(), Box<dyn std::error::Error>> {
        let base = tempfile::tempdir()?;
        let root = base.path().join("root");
        std::fs::create_dir_all(root.join("dir.pcap"))?;
        std::fs::write(root.join("a.pcap"), b"x")?;
        std::fs::write(root.join("notes.txt"), b"x")?;
        let outside = base.path().join("outside.pcap");
        std::fs::write(&outside, b"x")?;
        std::os::unix::fs::symlink(&outside, root.join("out-link.pcap"))?;
        std::os::unix::fs::symlink(root.join("a.pcap"), root.join("in-link.pcap"))?;
        let got = listed_files(&root)?;
        assert_eq!(got, vec![(root.join("a.pcap"), ListedKind::Capture)]);
        Ok(())
    }
}
