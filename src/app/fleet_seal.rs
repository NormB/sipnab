// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! Encryption at rest for what `sipnab fleet serve` stores.
//!
//! The center never writes a file in clear. This module holds the pieces
//! every stored file shares: the master key and its file, key ids, a data
//! key per file wrapped under the master key, and the sealed log, an
//! append-only file of authenticated records.
//!
//! # The construction
//!
//! Nothing here is a new cipher mode. Every operation is AES-256-GCM from
//! `ring`, used the way vcon-server's envelope uses it:
//!
//! - The master key is 32 random bytes in a private file. HKDF-SHA-256 gives
//!   one wrapping key per [`Layer`], so a key of one layer opens nothing of
//!   the other.
//! - Each file has its own random data key, wrapped as a format byte, a
//!   12-byte random nonce, the ciphertext and a 16-byte tag, with the file's
//!   kind and id as associated data. A wrapped key copied into another file
//!   does not open.
//! - A data key seals the records of one file only, each under its position
//!   in the file as the nonce, so no nonce repeats under a key, with the
//!   file's id and format as associated data. A file is
//!   never appended to by a later process: [`open_log`] reads, and the
//!   caller writes a new file under a new data key.
//!
//! # Records removed from the end
//!
//! A file that may stop being written at any moment cannot tell a last
//! record that was removed from one that was never written, unless it
//! holds a count. From format 2 it does. The header has two count slots,
//! each the number of entries in the file and a tag under the data key.
//! An append ([`append_counted`]) writes its records and an end mark,
//! waits for the disk, and then writes the count that covers them into
//! the two slots in turn. [`open_log`] refuses a file that holds fewer
//! entries than its newest count ([`SealError::Cut`]).
//!
//! A center stopped while it writes a count leaves one slot that does not
//! authenticate. In that state the append the count was for is on disk
//! whole, after the entries the other slot counts, and nothing follows
//! it. [`open_log`] takes one failed slot in exactly that state and
//! refuses it in any other ([`SealError::Count`]), so damaging the newest
//! count does not make a removed append look like a crash.
//!
//! Two things no file can show on its own: that it was deleted, and that
//! an earlier copy of the whole file was put back.
//!
//! # What is pure and what is not
//!
//! [`MasterKey::parse`], [`wrap`], [`unwrap`], [`LogSealer`] and
//! [`open_log`] work on bytes and take their randomness as an argument.
//! [`read_key_file`], [`write_new_key_file`], [`append_counted`] and
//! [`system_draw`] are the four functions that touch the file system or
//! the system random source.

use std::path::Path;

use base64::Engine as _;
use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use sha2::Digest as _;
use zeroize::Zeroizing;

pub use crate::cli::fleet_args::Encryption;

/// Bytes in a master key and in a data key.
pub const KEY_BYTES: usize = 32;

/// The first bytes of every sealed file.
pub const MAGIC: [u8; 4] = *b"SNFS";

/// The sealed file format this build writes: a key header, two count
/// slots, then the records.
pub const FORMAT: u8 = 2;

/// The sealed file format of the releases before the count slots: a key
/// header, then the records. Read, and never written.
const FORMAT_UNCOUNTED: u8 = 1;

/// The format byte a wrapped data key starts with.
const WRAP_FORMAT: u8 = 1;

/// Bytes in an AES-GCM nonce.
const NONCE_BYTES: usize = 12;

/// Bytes in an AES-GCM tag.
const TAG_BYTES: usize = 16;

/// Bytes in a file id.
pub const FILE_ID_BYTES: usize = 16;

/// Bytes in a wrapped data key: format byte, nonce, key, tag.
pub const WRAPPED_BYTES: usize = 1 + NONCE_BYTES + KEY_BYTES + TAG_BYTES;

/// Bytes in the part of a sealed file's header that names its key: magic,
/// format, kind, key id, file id, wrapped data key.
pub const KEY_HEADER_BYTES: usize = MAGIC.len() + 1 + 1 + 8 + FILE_ID_BYTES + WRAPPED_BYTES;

/// Bytes in a count slot: a sealed count of the file's entries, and its
/// tag.
pub const COUNT_SLOT_BYTES: usize = 8 + TAG_BYTES;

/// Bytes in a sealed file's header: the key header, then two count slots.
pub const HEADER_BYTES: usize = KEY_HEADER_BYTES + 2 * COUNT_SLOT_BYTES;

/// The largest record a sealed log holds, in bytes.
///
/// Not a setting: the center's ingest body limit is 4 MiB, and a record is
/// one part of a body. The bound keeps a damaged length from asking for
/// gigabytes before the record is checked.
pub const MAX_RECORD_BYTES: usize = 8 * 1024 * 1024;

/// The first byte of a sealed record's plaintext: a stored record.
const FRAME_RECORD: u8 = 1;

/// The first byte of a sealed record's plaintext: the end of the records a
/// file was written with, followed by their count.
const FRAME_BASE_END: u8 = 2;

/// The first byte of a sealed record's plaintext: the end of one append.
/// With it a reader can tell a file that stopped between an append and its
/// count from one whose last append was removed, whole or in part.
const FRAME_APPEND_END: u8 = 3;

/// The label hashed before the key to give its id, so the id is no other
/// SHA-256 of the key.
const ID_DOMAIN: &[u8] = b"sipnab fleet store key id v1\0";

/// What a wrapped data key's associated data starts with.
const WRAP_DOMAIN: &[u8] = b"sipnab fleet store wrap v1\0";

/// A source of random bytes: asked for a count, it returns that many new
/// bytes, or says why it could not.
///
/// The bytes are returned and never written into a buffer the caller
/// prepared, so a source that gives nothing cannot leave a prepared value
/// in use as a key or a nonce. [`draw`] refuses any other count.
pub type Draw<'a> = &'a dyn Fn(usize) -> Result<Zeroizing<Vec<u8>>, String>;

/// `len` bytes from the system random source.
///
/// # Errors
///
/// The source failed. There is no weaker fallback.
pub fn system_draw(len: usize) -> Result<Zeroizing<Vec<u8>>, String> {
    let rng = ring::rand::SystemRandom::new();
    // Sized before it is filled, so the bytes are never moved and left
    // behind by a growing buffer.
    let mut out = Zeroizing::new(Vec::with_capacity(len));
    while out.len() < len {
        let block = ring::rand::generate::<[u8; KEY_BYTES]>(&rng)
            .map(|block| Zeroizing::new(block.expose()))
            .map_err(|_| "the system random source failed".to_string())?;
        let take = (len - out.len()).min(block.len());
        out.extend_from_slice(&block[..take]);
    }
    Ok(out)
}

/// Exactly `N` bytes from `source`.
///
/// # Errors
///
/// `source` failed, or returned another count of bytes than `N`. A short
/// answer is never completed with other bytes.
pub fn draw<const N: usize>(source: Draw<'_>) -> Result<Zeroizing<[u8; N]>, String> {
    let bytes = source(N)?;
    <[u8; N]>::try_from(bytes.as_slice())
        .map(Zeroizing::new)
        .map_err(|_| {
            format!(
                "the random source returned {} bytes where {N} were asked for",
                bytes.len()
            )
        })
}

/// The public name of a master key: 8 bytes of a SHA-256 over the key,
/// shown as 16 hex characters. Not secret; files and messages carry it.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct KeyId([u8; 8]);

impl std::fmt::Display for KeyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl std::fmt::Debug for KeyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "KeyId({self})")
    }
}

/// Which mechanism a key protects. Each has its own wrapping key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layer {
    /// A file sealed as one object by this module.
    Sealed,
    /// Parquet modular encryption.
    Modular,
}

impl Layer {
    /// The HKDF info string of this layer's wrapping key.
    const fn info(self) -> &'static [u8] {
        match self {
            Self::Sealed => b"sipnab fleet store sealed v1",
            Self::Modular => b"sipnab fleet store modular v1",
        }
    }

    /// The byte that names this layer in associated data.
    const fn byte(self) -> u8 {
        match self {
            Self::Sealed => 1,
            Self::Modular => 2,
        }
    }
}

/// What a sealed file holds. Bound into the file's key, so a file of one
/// kind put in the place of another does not open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// The center's member registry (`--store`).
    Registry,
    /// Batches the center acknowledged and has not yet filed.
    Intake,
    /// A delivery waiting in a member's spool.
    Spool,
    /// A Parquet file of call records in the center's history store.
    Calls,
}

impl Kind {
    /// The byte that names this kind in a header.
    const fn byte(self) -> u8 {
        match self {
            Self::Registry => 1,
            Self::Intake => 2,
            Self::Spool => 3,
            Self::Calls => 4,
        }
    }

    /// The name of this kind in a message.
    const fn name(self) -> &'static str {
        match self {
            Self::Registry => "registry",
            Self::Intake => "intake",
            Self::Spool => "spool",
            Self::Calls => "calls",
        }
    }

    /// The kind `byte` names, if any.
    const fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Self::Registry),
            2 => Some(Self::Intake),
            3 => Some(Self::Spool),
            4 => Some(Self::Calls),
            _ => None,
        }
    }
}

/// The public name of the key `bytes`.
fn key_id(bytes: &[u8; KEY_BYTES]) -> KeyId {
    let digest = sha2::Sha256::new()
        .chain_update(ID_DOMAIN)
        .chain_update(bytes)
        .finalize();
    let mut id = [0u8; 8];
    id.copy_from_slice(&digest[..8]);
    KeyId(id)
}

/// The output length HKDF is asked for: one key.
struct OneKey;

impl ring::hkdf::KeyType for OneKey {
    fn len(&self) -> usize {
        KEY_BYTES
    }
}

/// A master key: the secret every stored file's data key is wrapped under.
pub struct MasterKey {
    /// The key.
    bytes: Zeroizing<[u8; KEY_BYTES]>,
    /// Its public name.
    id: KeyId,
}

impl std::fmt::Debug for MasterKey {
    /// Prints the key id and never the key.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MasterKey")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl MasterKey {
    /// The key made of `bytes`.
    #[must_use]
    pub fn from_bytes(bytes: [u8; KEY_BYTES]) -> Self {
        let bytes = Zeroizing::new(bytes);
        Self {
            id: key_id(&bytes),
            bytes,
        }
    }

    /// The key a key file's text holds: 32 bytes in standard base64, with
    /// white space around it ignored.
    ///
    /// # Errors
    ///
    /// The text is not base64, or does not decode to 32 bytes. The message
    /// gives the length found and never the text.
    pub fn parse(text: &str) -> Result<Self, String> {
        let decoded = Zeroizing::new(
            base64::engine::general_purpose::STANDARD
                .decode(text.trim())
                .map_err(|_| "is not a key: it is not standard base64".to_string())?,
        );
        if decoded.len() != KEY_BYTES {
            return Err(format!(
                "is not a key: it holds {} bytes, and a key is {KEY_BYTES}",
                decoded.len()
            ));
        }
        let mut bytes = Zeroizing::new([0u8; KEY_BYTES]);
        bytes.copy_from_slice(&decoded);
        Ok(Self {
            id: key_id(&bytes),
            bytes,
        })
    }

    /// The text of this key's file: base64 and a newline.
    #[must_use]
    pub fn encode(&self) -> Zeroizing<String> {
        // Sized before it is filled, so the text is never moved and left
        // behind in freed memory.
        let mut text = Zeroizing::new(String::with_capacity(KEY_BYTES * 2));
        base64::engine::general_purpose::STANDARD.encode_string(*self.bytes, &mut text);
        text.push('\n');
        text
    }

    /// This key's public name.
    #[must_use]
    pub fn id(&self) -> KeyId {
        self.id
    }

    /// The key that wraps data keys of `layer`.
    fn wrapping_key(&self, layer: Layer) -> Result<Zeroizing<[u8; KEY_BYTES]>, String> {
        let mut out = Zeroizing::new([0u8; KEY_BYTES]);
        ring::hkdf::Salt::new(ring::hkdf::HKDF_SHA256, &[])
            .extract(&*self.bytes)
            .expand(&[layer.info()], OneKey)
            .and_then(|okm| okm.fill(&mut *out))
            .map_err(|_| "the key derivation failed".to_string())?;
        Ok(out)
    }
}

/// The keys a center holds: the one it writes under, and the earlier ones
/// it can still read under.
#[derive(Debug)]
pub struct Keys {
    /// `--store-key-file`.
    current: MasterKey,
    /// `--store-old-key-file`, each.
    old: Vec<MasterKey>,
}

impl Keys {
    /// `current` to write under and `old` to read under.
    #[must_use]
    pub fn new(current: MasterKey, old: Vec<MasterKey>) -> Self {
        Self { current, old }
    }

    /// The key new files are written under.
    #[must_use]
    pub fn current(&self) -> &MasterKey {
        &self.current
    }

    /// The key named `id`, the current one first.
    #[must_use]
    pub fn find(&self, id: KeyId) -> Option<&MasterKey> {
        std::iter::once(&self.current)
            .chain(&self.old)
            .find(|key| key.id() == id)
    }
}

/// Why a sealed file was refused. The text names no file; the caller
/// prefixes the layer and the file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SealError {
    /// The bytes do not start with [`MAGIC`].
    NotSealed,
    /// The format byte is one this build does not read.
    UnknownFormat(u8),
    /// The file is of another kind than the one asked for.
    WrongKind {
        /// The kind byte the header carries.
        found: u8,
        /// The kind that was asked for.
        wanted: Kind,
    },
    /// The file was written under a key that is not loaded.
    KeyNotLoaded(KeyId),
    /// The header's wrapped key did not authenticate.
    Header,
    /// The record at this position, from 1, did not authenticate.
    Record(u64),
    /// The file ends before the records it was written with do.
    Truncated,
    /// Neither count slot authenticated.
    Count,
    /// The file holds fewer entries than its count says: entries were
    /// removed from its end.
    Cut {
        /// The entries the file holds.
        held: u64,
        /// The entries its newest count covers.
        counted: u64,
    },
    /// The cipher itself failed, which no input should cause.
    Cipher,
}

impl std::fmt::Display for SealError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotSealed => write!(f, "is not a sealed file"),
            Self::UnknownFormat(v) => write!(
                f,
                "has sealed format {v}, and this build reads format {FORMAT}"
            ),
            Self::WrongKind { found, wanted } => write!(
                f,
                "is a sealed {} file, not a {} file",
                Kind::from_byte(*found).map_or("unknown", Kind::name),
                wanted.name()
            ),
            Self::KeyNotLoaded(id) => {
                write!(f, "was written under key id {id}, which is not loaded")
            }
            Self::Header => write!(
                f,
                "has a header that did not authenticate (the file was modified, or the key is \
                 wrong)"
            ),
            Self::Record(n) => write!(
                f,
                "has a record {n} that did not authenticate (the file was modified, or its \
                 records were moved)"
            ),
            Self::Truncated => write!(f, "was truncated: it ends before its records do"),
            Self::Count => write!(
                f,
                "has a record count that did not authenticate (the file was modified, or the key \
                 is wrong)"
            ),
            Self::Cut { held, counted } => write!(
                f,
                "was cut at its end: it holds {held} of the {counted} entries it was written with"
            ),
            Self::Cipher => write!(f, "could not be processed: the cipher failed"),
        }
    }
}

/// The cipher under `key`.
fn cipher(key: &[u8; KEY_BYTES]) -> Result<LessSafeKey, SealError> {
    UnboundKey::new(&AES_256_GCM, key)
        .map(LessSafeKey::new)
        .map_err(|_| SealError::Cipher)
}

/// What a wrapped data key is bound to: its layer, and its file's kind and
/// id.
fn wrap_aad(layer: Layer, kind: Kind, file_id: &[u8; FILE_ID_BYTES]) -> Vec<u8> {
    let mut aad = WRAP_DOMAIN.to_vec();
    aad.extend([layer.byte(), kind.byte()]);
    aad.extend(file_id);
    aad
}

/// What a sealed record's associated data binds it to: its file. Its
/// position in the file is bound by its nonce ([`position_nonce`]), so a
/// record moved within a file fails as one moved between files does.
///
/// From format 2 the format is bound too, so the records of a file of one
/// format do not open behind the header of another.
fn record_aad(file_id: &[u8; FILE_ID_BYTES], format: u8) -> Vec<u8> {
    let mut aad = file_id.to_vec();
    if format != FORMAT_UNCOUNTED {
        aad.push(format);
    }
    aad
}

/// The nonce of the count `count` in the count slot `slot`. Its first four
/// bytes are never zero, and a record's always are ([`position_nonce`]), so
/// a count and a record never share a nonce; and the two slots never share
/// one either.
fn count_nonce(slot: usize, count: u64) -> [u8; NONCE_BYTES] {
    let mut nonce = [0u8; NONCE_BYTES];
    nonce[3] = if slot == 0 { 1 } else { 2 };
    nonce[NONCE_BYTES - 8..].copy_from_slice(&count.to_be_bytes());
    nonce
}

/// The count slot `slot` holding `count` for the file `file_id`: the count
/// itself, which is no secret, and a tag under `key`. The tag is bound to
/// the file and the format by its associated data, and to the slot and the
/// count by its nonce ([`count_nonce`]), so a slot with another count in it
/// does not authenticate.
fn seal_count(
    key: &LessSafeKey,
    file_id: &[u8; FILE_ID_BYTES],
    slot: usize,
    count: u64,
) -> Result<[u8; COUNT_SLOT_BYTES], String> {
    let mut tag = Vec::with_capacity(TAG_BYTES);
    key.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(count_nonce(slot, count)),
        Aad::from(record_aad(file_id, FORMAT)),
        &mut tag,
    )
    .map_err(|_| SealError::Cipher.to_string())?;
    let mut out = count.to_be_bytes().to_vec();
    out.extend(tag);
    <[u8; COUNT_SLOT_BYTES]>::try_from(out.as_slice()).map_err(|_| SealError::Cipher.to_string())
}

/// The count the slot `slot` holds in `bytes`, when its tag authenticates
/// under `key` for the file `file_id`.
fn open_count(
    key: &LessSafeKey,
    file_id: &[u8; FILE_ID_BYTES],
    slot: usize,
    bytes: &[u8],
) -> Option<u64> {
    let (count, tag) = bytes.split_first_chunk::<8>()?;
    let count = u64::from_be_bytes(*count);
    let mut tag = tag.to_vec();
    key.open_in_place(
        Nonce::assume_unique_for_key(count_nonce(slot, count)),
        Aad::from(record_aad(file_id, FORMAT)),
        &mut tag,
    )
    .ok()
    .map(|_| count)
}

/// Wrap `data_key` under `master` for a file of `kind` with id `file_id`.
///
/// # Errors
///
/// The cipher failed.
pub fn wrap(
    master: &MasterKey,
    layer: Layer,
    kind: Kind,
    file_id: &[u8; FILE_ID_BYTES],
    data_key: &[u8; KEY_BYTES],
    nonce: [u8; NONCE_BYTES],
) -> Result<[u8; WRAPPED_BYTES], SealError> {
    let wrapping = master.wrapping_key(layer).map_err(|_| SealError::Cipher)?;
    let mut sealed = data_key.to_vec();
    cipher(&wrapping)?
        .seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(wrap_aad(layer, kind, file_id)),
            &mut sealed,
        )
        .map_err(|_| SealError::Cipher)?;
    let mut out = [0u8; WRAPPED_BYTES];
    out[0] = WRAP_FORMAT;
    out[1..=NONCE_BYTES].copy_from_slice(&nonce);
    out[1 + NONCE_BYTES..].copy_from_slice(&sealed);
    Ok(out)
}

/// The data key `wrapped` holds, for a file of `kind` with id `file_id`.
///
/// # Errors
///
/// [`SealError::Header`] when it does not authenticate: another key, kind,
/// layer or file, or modified bytes.
pub fn unwrap(
    master: &MasterKey,
    layer: Layer,
    kind: Kind,
    file_id: &[u8; FILE_ID_BYTES],
    wrapped: &[u8; WRAPPED_BYTES],
) -> Result<Zeroizing<[u8; KEY_BYTES]>, SealError> {
    if wrapped[0] != WRAP_FORMAT {
        return Err(SealError::Header);
    }
    let nonce =
        <[u8; NONCE_BYTES]>::try_from(&wrapped[1..=NONCE_BYTES]).map_err(|_| SealError::Header)?;
    let wrapping = master.wrapping_key(layer).map_err(|_| SealError::Cipher)?;
    let mut sealed = Zeroizing::new(wrapped[1 + NONCE_BYTES..].to_vec());
    let opened = cipher(&wrapping)?
        .open_in_place(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(wrap_aad(layer, kind, file_id)),
            &mut sealed,
        )
        .map_err(|_| SealError::Header)?;
    <[u8; KEY_BYTES]>::try_from(&*opened)
        .map(Zeroizing::new)
        .map_err(|_| SealError::Header)
}

/// Seals the records of one new file. Its data key is used for this file
/// and no other.
pub struct LogSealer {
    /// The file's data key.
    key: LessSafeKey,
    /// The file's id.
    file_id: [u8; FILE_ID_BYTES],
    /// The position of the next record, from 0.
    next: u64,
    /// Records sealed so far.
    records: u64,
    /// The count slot the next count goes to: 0 or 1.
    slot: usize,
    /// The entries the newest count slot covers.
    counted: u64,
}

impl std::fmt::Debug for LogSealer {
    /// Prints the position and never the key.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LogSealer")
            .field("next", &self.next)
            .finish_non_exhaustive()
    }
}

impl LogSealer {
    /// A sealer for a new file of `kind` under `master`, and the header the
    /// file starts with. `source` supplies the file id, the data key and
    /// the wrap nonce.
    ///
    /// # Errors
    ///
    /// `source` failed or returned another count of bytes than it was
    /// asked for, or the cipher failed.
    pub fn new(
        master: &MasterKey,
        kind: Kind,
        source: Draw<'_>,
    ) -> Result<(Self, [u8; HEADER_BYTES]), String> {
        let file_id = *draw::<FILE_ID_BYTES>(source)?;
        let data_key = draw::<KEY_BYTES>(source)?;
        let nonce = *draw::<NONCE_BYTES>(source)?;
        let wrapped = wrap(master, Layer::Sealed, kind, &file_id, &data_key, nonce)
            .map_err(|e| e.to_string())?;
        let key = cipher(&data_key).map_err(|e| e.to_string())?;
        let mut header = [0u8; HEADER_BYTES];
        header[..4].copy_from_slice(&MAGIC);
        header[4] = FORMAT;
        header[5] = kind.byte();
        header[6..14].copy_from_slice(&master.id().0);
        header[14..14 + FILE_ID_BYTES].copy_from_slice(&file_id);
        header[14 + FILE_ID_BYTES..KEY_HEADER_BYTES].copy_from_slice(&wrapped);
        // Both slots start at a count of nothing, so a new file always has
        // a slot that authenticates.
        for slot in 0..2 {
            let at = KEY_HEADER_BYTES + slot * COUNT_SLOT_BYTES;
            header[at..at + COUNT_SLOT_BYTES]
                .copy_from_slice(&seal_count(&key, &file_id, slot, 0)?);
        }
        let sealer = Self {
            key,
            file_id,
            next: 0,
            records: 0,
            slot: 1,
            counted: 0,
        };
        Ok((sealer, header))
    }

    /// The bytes that end one append. They go to the file after the
    /// append's records and before its count.
    ///
    /// # Errors
    ///
    /// The cipher failed.
    pub fn append_end(&mut self) -> Result<Vec<u8>, String> {
        self.frame(FRAME_APPEND_END, &[])
    }

    /// The count slot that says the file holds every entry sealed so far,
    /// and the offset in the file it is written at. An append writes it
    /// once its records are on disk, so the count never runs ahead of the
    /// file; the two slots take turns, so a slot whose write did not finish
    /// leaves the count before it in the other.
    ///
    /// # Errors
    ///
    /// The cipher failed.
    pub fn count_slot(&mut self) -> Result<(usize, [u8; COUNT_SLOT_BYTES]), String> {
        let slot = seal_count(&self.key, &self.file_id, self.slot, self.next)?;
        let at = KEY_HEADER_BYTES + self.slot * COUNT_SLOT_BYTES;
        self.slot = 1 - self.slot;
        self.counted = self.next;
        Ok((at, slot))
    }

    /// The entries the newest count slot covers: records, and the end of
    /// the base.
    #[must_use]
    pub fn counted(&self) -> u64 {
        self.counted
    }

    /// The bytes that store `payload`, marked `tag`, at the next position:
    /// a length, then the sealed tag and payload.
    fn frame(&mut self, tag: u8, payload: &[u8]) -> Result<Vec<u8>, String> {
        let mut body = Vec::with_capacity(1 + payload.len() + TAG_BYTES);
        body.push(tag);
        body.extend_from_slice(payload);
        self.key
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(position_nonce(self.next)),
                Aad::from(record_aad(&self.file_id, FORMAT)),
                &mut body,
            )
            .map_err(|_| SealError::Cipher.to_string())?;
        let len = u32::try_from(body.len()).map_err(|_| "the record is too large".to_string())?;
        // A position is used once: the nonce of the next record is the
        // next position, and a file that ran out of them takes no more.
        self.next = self.next.checked_add(1).ok_or("the sealed file is full")?;
        let mut out = Vec::with_capacity(4 + body.len());
        out.extend(len.to_be_bytes());
        out.extend(body);
        Ok(out)
    }

    /// The bytes that store `record` at the next position.
    ///
    /// # Errors
    ///
    /// `record` is over [`MAX_RECORD_BYTES`], or the cipher failed.
    pub fn record(&mut self, record: &[u8]) -> Result<Vec<u8>, String> {
        if record.len() > MAX_RECORD_BYTES {
            return Err(format!(
                "a record of {} bytes is over the {MAX_RECORD_BYTES} a sealed file holds",
                record.len()
            ));
        }
        let out = self.frame(FRAME_RECORD, record)?;
        self.records += 1;
        Ok(out)
    }

    /// The bytes that end the records the file is first written with. A
    /// reader that does not find them knows the file was cut short.
    ///
    /// # Errors
    ///
    /// The cipher failed.
    pub fn base_end(&mut self) -> Result<Vec<u8>, String> {
        let count = self.records.to_be_bytes();
        self.frame(FRAME_BASE_END, &count)
    }
}

/// The nonce of the record at `position` in a file.
fn position_nonce(position: u64) -> [u8; NONCE_BYTES] {
    let mut nonce = [0u8; NONCE_BYTES];
    nonce[NONCE_BYTES - 8..].copy_from_slice(&position.to_be_bytes());
    nonce
}

/// What [`open_log`] read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenedLog {
    /// The records, in order.
    pub records: Vec<Vec<u8>>,
    /// The key the file was written under.
    pub key_id: KeyId,
    /// Whether the file ends in a record that was only partly written: an
    /// append the writer did not finish, and so never acknowledged.
    pub torn_tail: bool,
}

/// Read a sealed log of `kind` from `bytes`.
///
/// # Errors
///
/// A [`SealError`]: the bytes are not a sealed file of that kind, the key
/// is not in `keys`, or the header or a record did not authenticate, or the
/// file ends before the records it was first written with.
pub fn open_log(bytes: &[u8], keys: &Keys, kind: Kind) -> Result<OpenedLog, SealError> {
    if bytes.len() < MAGIC.len() || bytes[..MAGIC.len()] != MAGIC {
        return Err(SealError::NotSealed);
    }
    let format = bytes.get(4).copied();
    if let Some(format) = format
        && format != FORMAT
        && format != FORMAT_UNCOUNTED
    {
        return Err(SealError::UnknownFormat(format));
    }
    let header_bytes = if format == Some(FORMAT_UNCOUNTED) {
        KEY_HEADER_BYTES
    } else {
        HEADER_BYTES
    };
    if bytes.len() < header_bytes {
        return Err(SealError::Truncated);
    }
    let format = bytes[4];
    if bytes[5] != kind.byte() {
        return Err(SealError::WrongKind {
            found: bytes[5],
            wanted: kind,
        });
    }
    let mut id = [0u8; 8];
    id.copy_from_slice(&bytes[6..14]);
    let key_id = KeyId(id);
    let master = keys.find(key_id).ok_or(SealError::KeyNotLoaded(key_id))?;
    let mut file_id = [0u8; FILE_ID_BYTES];
    file_id.copy_from_slice(&bytes[14..14 + FILE_ID_BYTES]);
    let mut wrapped = [0u8; WRAPPED_BYTES];
    wrapped.copy_from_slice(&bytes[14 + FILE_ID_BYTES..KEY_HEADER_BYTES]);
    let data_key = unwrap(master, Layer::Sealed, kind, &file_id, &wrapped)?;
    let key = cipher(&data_key)?;
    let aad = record_aad(&file_id, format);
    // The entries the file must hold: the newest count that authenticates.
    // A format 1 file has no count.
    let (counted, one_count) = if format == FORMAT_UNCOUNTED {
        (0, false)
    } else {
        let counts: Vec<u64> = (0..2)
            .filter_map(|slot| {
                let at = KEY_HEADER_BYTES + slot * COUNT_SLOT_BYTES;
                open_count(&key, &file_id, slot, &bytes[at..at + COUNT_SLOT_BYTES])
            })
            .collect();
        let newest = counts.iter().copied().max().ok_or(SealError::Count)?;
        (newest, counts.len() == 1)
    };

    let mut log = OpenedLog {
        records: Vec::new(),
        key_id,
        torn_tail: false,
    };
    let mut rest = &bytes[header_bytes..];
    let mut position = 0u64;
    let mut base_ended = false;
    let mut ends_an_append = false;
    while !rest.is_empty() {
        let failed = SealError::Record(position.saturating_add(1));
        // A record that is only partly there is an append the writer did
        // not finish. Inside the base it means the file was cut.
        let Some((len, after)) = rest.split_first_chunk::<4>() else {
            log.torn_tail = true;
            break;
        };
        let len = usize::try_from(u32::from_be_bytes(*len)).map_err(|_| failed.clone())?;
        if !(1 + TAG_BYTES..=1 + MAX_RECORD_BYTES + TAG_BYTES).contains(&len) {
            return Err(failed);
        }
        if after.len() < len {
            log.torn_tail = true;
            break;
        }
        let mut body = after[..len].to_vec();
        let plain = key
            .open_in_place(
                Nonce::assume_unique_for_key(position_nonce(position)),
                Aad::from(aad.as_slice()),
                &mut body,
            )
            .map_err(|_| failed.clone())?;
        match plain.split_first() {
            Some((&FRAME_RECORD, payload)) => log.records.push(payload.to_vec()),
            Some((&FRAME_BASE_END, count))
                if !base_ended
                    && u64::try_from(log.records.len())
                        .is_ok_and(|n| n.to_be_bytes().as_slice() == count) =>
            {
                base_ended = true;
            }
            Some((&FRAME_APPEND_END, [])) if format != FORMAT_UNCOUNTED => {}
            _ => return Err(failed),
        }
        ends_an_append = plain.first() == Some(&FRAME_APPEND_END);
        position = position.checked_add(1).ok_or(failed)?;
        rest = &after[len..];
    }
    // A counted entry was on disk whole before it was counted, so a file
    // that holds fewer was cut, whether or not the cut left a part of one.
    if position < counted {
        return Err(SealError::Cut {
            held: position,
            counted,
        });
    }
    // One count that does not authenticate is what a crash leaves while a
    // count is written, and only then: the append it was to cover is on
    // disk whole, after the entries the other count covers, and nothing
    // follows it. Any other file with a damaged count was modified.
    if one_count && !(position > counted && ends_an_append && !log.torn_tail) {
        return Err(SealError::Count);
    }
    if !base_ended {
        return Err(SealError::Truncated);
    }
    Ok(log)
}

/// Append `frames`, records `sealer` sealed, to the sealed file at `path`
/// as one append: the records and the end of the append, synced, and then
/// the count that covers them, synced too. No `frames`, nothing written.
///
/// The order is the rule: the count never says more than the file holds,
/// so a crash at any point leaves a file that opens, and a file that holds
/// less than its count was cut by someone ([`SealError::Cut`]).
///
/// # Errors
///
/// The file cannot be opened, written or synced, or the end or the count
/// cannot be sealed. The file is not created when it is absent.
pub fn append_counted(path: &Path, sealer: &mut LogSealer, frames: &[u8]) -> std::io::Result<()> {
    if frames.is_empty() {
        return Ok(());
    }
    append_counted_to(&mut *open_for_append(path)?, sealer, frames)
}

/// A sealed file open for an append: written, moved in, and synced.
///
/// The appends go through this and not through [`std::fs::File`] itself so
/// that a test can stand a file that fails part way in its place: a write
/// that stops short, a full disk, a sync that fails.
pub trait LogFile: std::io::Write + std::io::Seek {
    /// Wait until what was written is on disk.
    ///
    /// # Errors
    ///
    /// The sync failed.
    fn sync(&mut self) -> std::io::Result<()>;
}

impl LogFile for std::fs::File {
    fn sync(&mut self) -> std::io::Result<()> {
        self.sync_data()
    }
}

/// Open the sealed file at `path` for an append.
///
/// # Errors
///
/// The file cannot be opened for writing. It is not created when absent.
pub fn open_for_append(path: &Path) -> std::io::Result<Box<dyn LogFile>> {
    let file = std::fs::OpenOptions::new().write(true).open(path)?;
    Ok(Box::new(file))
}

/// [`append_counted`] on a file that is already open. `frames` is not
/// empty.
///
/// When this fails, `sealer` is past what `file` holds and must seal
/// nothing more for it: the file is read and written again under a new
/// data key first ([`crate::app::fleet_log::AppendLog`] does that).
///
/// # Errors
///
/// The file cannot be written or synced, or the end or the count cannot be
/// sealed.
pub fn append_counted_to(
    file: &mut dyn LogFile,
    sealer: &mut LogSealer,
    frames: &[u8],
) -> std::io::Result<()> {
    use std::io::SeekFrom;
    let end = sealer.append_end().map_err(std::io::Error::other)?;
    file.seek(SeekFrom::End(0))?;
    file.write_all(&[frames, &end].concat())?;
    file.sync()?;
    let (at, slot) = sealer.count_slot().map_err(std::io::Error::other)?;
    file.seek(SeekFrom::Start(at as u64))?;
    file.write_all(&slot)?;
    file.sync()
}

/// Read the master key in the file `path`, which the flag `flag` named.
///
/// # Errors
///
/// The file is missing, is readable by others, or does not hold a key. The
/// message names the flag, the file and the fix, and never the contents.
pub fn read_key_file(path: &Path, flag: &str) -> Result<MasterKey, String> {
    use std::io::Read as _;
    let shown = path.display();
    let hint = "create a key with `sipnab fleet keygen --out FILE`";
    let mut file = crate::privilege::open_private_file(path, flag).map_err(|why| {
        if path.exists() {
            why
        } else {
            format!("{why}; {hint}")
        }
    })?;
    let mut text = Zeroizing::new(String::with_capacity(4 * KEY_BYTES));
    file.read_to_string(&mut text)
        .map_err(|_| format!("{flag} '{shown}' is not a key: it could not be read as text"))?;
    MasterKey::parse(&text).map_err(|why| format!("{flag} '{shown}' {why}; {hint}"))
}

/// Create the file `path`, readable by this user only, holding a new master
/// key from `source`, and return the key's id.
///
/// # Errors
///
/// `path` exists, cannot be created or written, or `source` failed or
/// returned another count of bytes than a key has. An existing file is
/// never overwritten: it may be the only copy of a key.
pub fn write_new_key_file(path: &Path, source: Draw<'_>) -> Result<KeyId, String> {
    use std::io::Write as _;
    let shown = path.display();
    // The key is drawn first: a random source that fails leaves no file.
    let bytes = draw::<KEY_BYTES>(source).map_err(|e| format!("--out '{shown}': {e}"))?;
    let key = MasterKey::from_bytes(*bytes);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|e| format!("--out '{shown}': {e}"))?;
    file.write_all(key.encode().as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|e| {
            let _ = std::fs::remove_file(path);
            format!("--out '{shown}': {e}")
        })?;
    Ok(key.id())
}

/// A format 1 file of `kind` under `master`, for tests: `records`, the end
/// of the base, then `appended`, written the way the releases before the
/// count slots wrote it, up to 0.5.245. This build writes no such file, so
/// the tests of reading one build it here; it was compared byte for byte
/// with the writer of release 0.5.244 when the format changed, and
/// `tests/fixtures/fleet/center-store-format-1.sealed` is a file that
/// writer made. Release 0.5.245 writes the same format.
///
/// # Errors
///
/// `source` failed, or the cipher did.
#[cfg(test)]
pub(crate) fn sealed_format_1(
    kind: Kind,
    master: &MasterKey,
    records: &[&[u8]],
    appended: &[&[u8]],
    source: Draw<'_>,
) -> Result<Vec<u8>, String> {
    let file_id = *draw::<FILE_ID_BYTES>(source)?;
    let data_key = draw::<KEY_BYTES>(source)?;
    let nonce = *draw::<NONCE_BYTES>(source)?;
    let wrapped =
        wrap(master, Layer::Sealed, kind, &file_id, &data_key, nonce).map_err(|e| e.to_string())?;
    let cipher = cipher(&data_key).map_err(|e| e.to_string())?;
    let mut out = MAGIC.to_vec();
    out.extend([FORMAT_UNCOUNTED, kind.byte()]);
    out.extend(master.id().0);
    out.extend(file_id);
    out.extend(wrapped);
    let count = (records.len() as u64).to_be_bytes();
    let frames = records
        .iter()
        .map(|r| (FRAME_RECORD, *r))
        .chain(std::iter::once((FRAME_BASE_END, count.as_slice())))
        .chain(appended.iter().map(|r| (FRAME_RECORD, *r)));
    for (position, (tag, payload)) in frames.enumerate() {
        let mut body = vec![tag];
        body.extend_from_slice(payload);
        cipher
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(position_nonce(position as u64)),
                Aad::from(file_id),
                &mut body,
            )
            .map_err(|_| "seal".to_string())?;
        out.extend((body.len() as u32).to_be_bytes());
        out.extend(body);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What a test returns.
    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// A key whose every byte is `b`.
    fn key(b: u8) -> MasterKey {
        MasterKey::from_bytes([b; KEY_BYTES])
    }

    /// A source that returns a counter, so every call gives different
    /// bytes and a test is repeatable.
    fn counting() -> impl Fn(usize) -> Result<Zeroizing<Vec<u8>>, String> {
        let next = std::cell::Cell::new(1u8);
        move |len: usize| {
            Ok(Zeroizing::new(
                (0..len)
                    .map(|_| next.replace(next.get().wrapping_add(1)))
                    .collect(),
            ))
        }
    }

    /// Twelve bytes from [`counting`], for a wrap that needs a nonce.
    fn drawn() -> Result<[u8; NONCE_BYTES], String> {
        draw::<NONCE_BYTES>(&counting()).map(|nonce| *nonce)
    }

    /// A sealed registry file under `master` holding `records`, then
    /// `appended` after the end of the base.
    fn sealed(
        master: &MasterKey,
        records: &[&[u8]],
        appended: &[&[u8]],
    ) -> Result<Vec<u8>, String> {
        let source = counting();
        let (mut sealer, header) = LogSealer::new(master, Kind::Registry, &source)?;
        let mut out = header.to_vec();
        for r in records {
            out.extend(sealer.record(r)?);
        }
        out.extend(sealer.base_end()?);
        for r in appended {
            out.extend(sealer.record(r)?);
        }
        Ok(out)
    }

    /// The keys with `current` and nothing older.
    fn only(current: MasterKey) -> Keys {
        Keys::new(current, Vec::new())
    }

    // ---- success ----

    #[test]
    fn a_key_survives_its_file_text() -> TestResult {
        let k = key(7);
        let back = MasterKey::parse(&k.encode())?;
        assert_eq!(
            back.id(),
            k.id(),
            "the parsed key has the id of the one encoded"
        );
        assert_eq!(
            *back.bytes, [7; KEY_BYTES],
            "the parsed key has the bytes of the one encoded"
        );
        Ok(())
    }

    #[test]
    fn a_key_id_is_16_hex_characters_and_stable() {
        let a = key(7).id().to_string();
        assert_eq!(a.len(), 16, "a key id is 8 bytes in hex");
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()), "a key id is hex");
        assert_eq!(
            a,
            key(7).id().to_string(),
            "the id of a key does not change between calls"
        );
    }

    #[test]
    fn a_wrapped_data_key_unwraps_to_itself() -> TestResult {
        let (m, id, dek) = (key(1), [3; FILE_ID_BYTES], [9; KEY_BYTES]);
        let w = wrap(&m, Layer::Sealed, Kind::Registry, &id, &dek, drawn()?)
            .map_err(|e| e.to_string())?;
        assert_eq!(
            w[0], WRAP_FORMAT,
            "the envelope starts with its format byte"
        );
        let back = unwrap(&m, Layer::Sealed, Kind::Registry, &id, &w).map_err(|e| e.to_string())?;
        assert_eq!(*back, dek, "the unwrapped key is the one wrapped");
        Ok(())
    }

    #[test]
    fn a_log_returns_its_records_in_order() -> TestResult {
        let bytes = sealed(&key(1), &[b"one", b"two", b"three"], &[])?;
        let log = open_log(&bytes, &only(key(1)), Kind::Registry).map_err(|e| e.to_string())?;
        assert_eq!(
            log.records,
            vec![b"one".to_vec(), b"two".to_vec(), b"three".to_vec()],
            "every record, in the order sealed"
        );
        assert!(!log.torn_tail, "nothing was torn");
        assert_eq!(log.key_id, key(1).id(), "the log names the key it is under");
        Ok(())
    }

    #[test]
    fn a_log_opens_under_an_old_key() -> TestResult {
        let bytes = sealed(&key(1), &[b"kept"], &[])?;
        let keys = Keys::new(key(2), vec![key(1)]);
        let log = open_log(&bytes, &keys, Kind::Registry).map_err(|e| e.to_string())?;
        assert_eq!(
            log.records,
            vec![b"kept".to_vec()],
            "the record sealed under the old key"
        );
        assert_eq!(log.key_id, key(1).id(), "it says which key it was under");
        Ok(())
    }

    #[test]
    fn a_log_with_no_records_opens_empty() -> TestResult {
        let bytes = sealed(&key(1), &[], &[])?;
        let log = open_log(&bytes, &only(key(1)), Kind::Registry).map_err(|e| e.to_string())?;
        assert!(log.records.is_empty(), "no record was sealed");
        Ok(())
    }

    #[test]
    fn records_appended_after_the_base_are_read() -> TestResult {
        let bytes = sealed(&key(1), &[b"base"], &[b"later", b"last"])?;
        let log = open_log(&bytes, &only(key(1)), Kind::Registry).map_err(|e| e.to_string())?;
        assert_eq!(
            log.records,
            vec![b"base".to_vec(), b"later".to_vec(), b"last".to_vec()],
            "the base record, then the appended ones in order"
        );
        Ok(())
    }

    #[test]
    fn a_new_key_file_is_private_and_holds_the_key_it_names() -> TestResult {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("store.key");
        let id = write_new_key_file(&path, &counting())?;
        assert_eq!(
            std::fs::metadata(&path)?.permissions().mode() & 0o777,
            0o600,
            "a key file is for its owner only"
        );
        assert_eq!(
            read_key_file(&path, "--store-key-file")?.id(),
            id,
            "the file holds the key whose id was returned"
        );
        Ok(())
    }

    #[test]
    fn a_key_file_may_end_in_a_newline() -> TestResult {
        let text = key(4).encode();
        assert!(text.ends_with('\n'), "the file text ends in a newline");
        assert_eq!(
            MasterKey::parse(&text)?.id(),
            key(4).id(),
            "the newline is not part of the key"
        );
        Ok(())
    }

    #[test]
    fn sealed_is_available_in_this_build() {
        assert_eq!(
            Encryption::Sealed.unavailable(),
            None,
            "sealed runs in this build"
        );
        assert_eq!(
            Encryption::default(),
            Encryption::Sealed,
            "sealed is the default"
        );
    }

    #[test]
    fn each_layer_has_its_own_wrapping_key() -> TestResult {
        let m = key(1);
        let (a, b) = (
            m.wrapping_key(Layer::Sealed)?,
            m.wrapping_key(Layer::Modular)?,
        );
        assert_ne!(
            *a, *b,
            "a layer's wrapping key opens nothing of the other layer"
        );
        assert_ne!(*a, [1; KEY_BYTES], "and neither is the master key itself");
        Ok(())
    }

    #[test]
    fn a_sealed_file_holds_none_of_its_records_in_clear() -> TestResult {
        let member_record = b"edge-a.example.com +15550100";
        let bytes = sealed(&key(1), &[member_record], &[member_record])?;
        assert!(
            !bytes
                .windows(member_record.len())
                .any(|w| w == member_record),
            "the record is not in the file in clear"
        );
        assert!(
            !bytes.windows(7).any(|w| w == b"5550100"),
            "no part of the number is in the file in clear"
        );
        Ok(())
    }

    #[test]
    fn two_files_of_the_same_records_share_no_sealed_bytes() -> TestResult {
        let source = counting();
        let (mut a, ha) = LogSealer::new(&key(1), Kind::Registry, &source)?;
        let (mut b, hb) = LogSealer::new(&key(1), Kind::Registry, &source)?;
        assert_ne!(ha, hb, "a file id and a data key each");
        assert_ne!(
            a.record(b"same")?,
            b.record(b"same")?,
            "the same record under two data keys"
        );
        Ok(())
    }

    #[test]
    fn the_header_names_the_format_the_kind_and_the_key() -> TestResult {
        let bytes = sealed(&key(1), &[], &[])?;
        assert_eq!(&bytes[..4], b"SNFS", "the magic");
        assert_eq!(bytes[4], FORMAT, "the format byte");
        assert_eq!(bytes[5], Kind::Registry.byte(), "the kind byte");
        assert_eq!(&bytes[6..14], &key(1).id().0, "the key id");
        Ok(())
    }

    // ---- failure ----

    #[test]
    fn a_short_key_is_refused_by_its_length_and_not_shown() {
        let text = base64::engine::general_purpose::STANDARD.encode([7u8; 31]);
        let e = MasterKey::parse(&text).err().unwrap_or_default();
        assert!(e.contains("31 bytes") && e.contains("32"), "{e}");
        assert!(!e.contains(&text), "the text is never repeated: {e}");
    }

    #[test]
    fn a_key_that_is_not_base64_is_refused_and_not_shown() {
        let e = MasterKey::parse("not base64 at all!")
            .err()
            .unwrap_or_default();
        assert!(e.contains("base64"), "{e}");
        assert!(!e.contains("not base64 at all"), "{e}");
    }

    #[test]
    fn a_url_safe_key_is_refused() {
        // 32 bytes of 0xfb encode with '-' and '_' in the URL-safe alphabet.
        let text = base64::engine::general_purpose::URL_SAFE.encode([0xfbu8; KEY_BYTES]);
        assert!(
            text.contains('-') || text.contains('_'),
            "the test key must use the URL-safe alphabet's own characters"
        );
        assert!(
            MasterKey::parse(&text).is_err(),
            "only standard base64 is a key"
        );
    }

    #[test]
    fn a_missing_key_file_names_the_flag_the_file_and_the_fix() -> TestResult {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("absent.key");
        let e = read_key_file(&path, "--store-key-file")
            .err()
            .unwrap_or_default();
        assert!(e.contains("--store-key-file"), "{e}");
        assert!(e.contains("absent.key"), "{e}");
        assert!(e.contains("sipnab fleet keygen --out"), "{e}");
        Ok(())
    }

    #[test]
    fn a_key_file_others_can_read_is_refused() -> TestResult {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("store.key");
        write_new_key_file(&path, &counting())?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))?;
        let e = read_key_file(&path, "--store-key-file")
            .err()
            .unwrap_or_default();
        assert!(
            e.contains("store.key") && e.contains("--store-key-file"),
            "{e}"
        );
        Ok(())
    }

    #[test]
    fn a_key_file_holding_something_else_is_refused_without_its_contents() -> TestResult {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("store.key");
        std::fs::write(&path, "hunter2-not-a-key\n")?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        let e = read_key_file(&path, "--store-key-file")
            .err()
            .unwrap_or_default();
        assert!(e.contains("store.key"), "{e}");
        assert!(!e.contains("hunter2"), "{e}");
        Ok(())
    }

    #[test]
    fn keygen_never_overwrites_a_file() -> TestResult {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("store.key");
        std::fs::write(&path, "the only copy")?;
        let e = write_new_key_file(&path, &counting())
            .err()
            .unwrap_or_default();
        assert!(e.contains("store.key"), "{e}");
        assert_eq!(
            std::fs::read_to_string(&path)?,
            "the only copy",
            "the existing file is untouched"
        );
        Ok(())
    }

    #[test]
    fn keygen_reports_a_random_source_that_failed_and_leaves_no_file() -> TestResult {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("store.key");
        let failing = |_: usize| Err("no entropy".to_string());
        let e = write_new_key_file(&path, &failing)
            .err()
            .unwrap_or_default();
        assert!(e.contains("no entropy"), "{e}");
        assert!(!path.exists(), "no file holding a key that was never drawn");
        Ok(())
    }

    #[test]
    fn a_file_under_a_key_that_is_not_loaded_names_that_key_id() -> TestResult {
        let bytes = sealed(&key(1), &[b"r"], &[])?;
        let e = open_log(&bytes, &only(key(2)), Kind::Registry).err();
        assert_eq!(
            e,
            Some(SealError::KeyNotLoaded(key(1).id())),
            "the refusal carries the id of the key the file needs"
        );
        let text = e.map(|e| e.to_string()).unwrap_or_default();
        assert!(text.contains(&key(1).id().to_string()), "{text}");
        Ok(())
    }

    #[test]
    fn a_modified_wrapped_key_fails_the_header() -> TestResult {
        let mut bytes = sealed(&key(1), &[b"r"], &[])?;
        bytes[KEY_HEADER_BYTES - 20] ^= 1;
        assert_eq!(
            open_log(&bytes, &only(key(1)), Kind::Registry).err(),
            Some(SealError::Header),
            "a changed wrapped key fails the header"
        );
        Ok(())
    }

    #[test]
    fn a_modified_file_id_fails_the_header() -> TestResult {
        let mut bytes = sealed(&key(1), &[b"r"], &[])?;
        bytes[14] ^= 1;
        assert_eq!(
            open_log(&bytes, &only(key(1)), Kind::Registry).err(),
            Some(SealError::Header),
            "a changed file id fails the header"
        );
        Ok(())
    }

    #[test]
    fn a_modified_record_is_named_by_its_position() -> TestResult {
        let bytes = sealed(&key(1), &[b"first", b"second"], &[])?;
        let first_len = 4 + 1 + 5 + TAG_BYTES;
        let mut m = bytes.clone();
        m[HEADER_BYTES + first_len + 6] ^= 1;
        assert_eq!(
            open_log(&m, &only(key(1)), Kind::Registry).err(),
            Some(SealError::Record(2)),
            "the changed byte is in record 2"
        );
        let mut m = bytes;
        m[HEADER_BYTES + 5] ^= 1;
        assert_eq!(
            open_log(&m, &only(key(1)), Kind::Registry).err(),
            Some(SealError::Record(1)),
            "the changed byte is in record 1"
        );
        Ok(())
    }

    #[test]
    fn a_file_cut_inside_its_base_is_truncated() -> TestResult {
        let bytes = sealed(&key(1), &[b"first", b"second"], &[])?;
        let cut = &bytes[..HEADER_BYTES + 12];
        assert_eq!(
            open_log(cut, &only(key(1)), Kind::Registry).err(),
            Some(SealError::Truncated),
            "the file ends inside its first record"
        );
        Ok(())
    }

    #[test]
    fn a_file_cut_between_base_records_is_truncated() -> TestResult {
        let bytes = sealed(&key(1), &[b"first", b"second"], &[])?;
        let first_len = 4 + 1 + 5 + TAG_BYTES;
        let cut = &bytes[..HEADER_BYTES + first_len];
        assert_eq!(
            open_log(cut, &only(key(1)), Kind::Registry).err(),
            Some(SealError::Truncated),
            "whole records gone, and no torn record to hint at it"
        );
        Ok(())
    }

    #[test]
    fn a_file_of_another_kind_is_refused_by_kind() -> TestResult {
        let source = counting();
        let (mut sealer, header) = LogSealer::new(&key(1), Kind::Intake, &source)?;
        let mut bytes = header.to_vec();
        bytes.extend(sealer.base_end()?);
        let e = open_log(&bytes, &only(key(1)), Kind::Registry).err();
        assert_eq!(
            e,
            Some(SealError::WrongKind {
                found: Kind::Intake.byte(),
                wanted: Kind::Registry
            }),
            "the refusal says what the file is and what was asked for"
        );
        let text = e.map(|e| e.to_string()).unwrap_or_default();
        assert!(
            text.contains("intake") && text.contains("registry"),
            "{text}"
        );
        Ok(())
    }

    #[test]
    fn a_kind_byte_changed_to_pass_the_check_fails_the_header() -> TestResult {
        let source = counting();
        let (mut sealer, header) = LogSealer::new(&key(1), Kind::Intake, &source)?;
        let mut bytes = header.to_vec();
        bytes.extend(sealer.base_end()?);
        bytes[5] = Kind::Registry.byte();
        assert_eq!(
            open_log(&bytes, &only(key(1)), Kind::Registry).err(),
            Some(SealError::Header),
            "the kind is in the wrapped key's associated data"
        );
        Ok(())
    }

    #[test]
    fn two_records_that_changed_places_are_refused() -> TestResult {
        let bytes = sealed(&key(1), &[b"aaaaa", b"bbbbb"], &[])?;
        let len = 4 + 1 + 5 + TAG_BYTES;
        let (a, b) = (HEADER_BYTES, HEADER_BYTES + len);
        let mut m = bytes.clone();
        m[a..a + len].copy_from_slice(&bytes[b..b + len]);
        m[b..b + len].copy_from_slice(&bytes[a..a + len]);
        assert_eq!(
            open_log(&m, &only(key(1)), Kind::Registry).err(),
            Some(SealError::Record(1)),
            "record 1 holds record 2's bytes"
        );
        Ok(())
    }

    #[test]
    fn a_header_from_another_file_does_not_open_this_files_records() -> TestResult {
        let source = counting();
        let (mut a, _) = LogSealer::new(&key(1), Kind::Registry, &source)?;
        let (_, header_b) = LogSealer::new(&key(1), Kind::Registry, &source)?;
        let mut bytes = header_b.to_vec();
        bytes.extend(a.record(b"moved")?);
        bytes.extend(a.base_end()?);
        assert_eq!(
            open_log(&bytes, &only(key(1)), Kind::Registry).err(),
            Some(SealError::Record(1)),
            "the record was sealed for another file"
        );
        Ok(())
    }

    #[test]
    fn a_record_from_another_file_under_the_same_data_key_is_refused() -> TestResult {
        // Two files whose data keys are equal and whose ids differ, which
        // the system random source never gives: only the file id in the
        // record's associated data tells their records apart.
        let next = std::cell::Cell::new(1u8);
        let source = |len: usize| {
            let byte = if len == KEY_BYTES {
                0x42
            } else {
                next.replace(next.get() + 1)
            };
            Ok(Zeroizing::new(vec![byte; len]))
        };
        let (mut a, header_a) = LogSealer::new(&key(1), Kind::Registry, &source)?;
        let (mut b, header_b) = LogSealer::new(&key(1), Kind::Registry, &source)?;
        assert_ne!(header_a[14..30], header_b[14..30], "two file ids");
        let mut bytes = header_b.to_vec();
        bytes.extend(a.record(b"from file a")?);
        bytes.extend(b.frame(FRAME_BASE_END, &1u64.to_be_bytes())?);
        assert_eq!(
            open_log(&bytes, &only(key(1)), Kind::Registry).err(),
            Some(SealError::Record(1)),
            "the record was sealed for file a"
        );
        Ok(())
    }

    #[test]
    fn a_wrapped_key_does_not_unwrap_for_another_file_layer_or_kind() -> TestResult {
        let (m, id, dek) = (key(1), [3; FILE_ID_BYTES], [9; KEY_BYTES]);
        let w = wrap(&m, Layer::Sealed, Kind::Registry, &id, &dek, drawn()?)
            .map_err(|e| e.to_string())?;
        let other = [4; FILE_ID_BYTES];
        assert!(
            unwrap(&m, Layer::Sealed, Kind::Registry, &other, &w).is_err(),
            "another file id"
        );
        assert!(
            unwrap(&m, Layer::Modular, Kind::Registry, &id, &w).is_err(),
            "another layer"
        );
        assert!(
            unwrap(&m, Layer::Sealed, Kind::Intake, &id, &w).is_err(),
            "another kind"
        );
        assert!(
            unwrap(&key(2), Layer::Sealed, Kind::Registry, &id, &w).is_err(),
            "another master key"
        );
        Ok(())
    }

    #[test]
    fn a_wrapped_key_of_an_unknown_envelope_format_is_refused() -> TestResult {
        let (m, id, dek) = (key(1), [3; FILE_ID_BYTES], [9; KEY_BYTES]);
        let mut w = wrap(&m, Layer::Sealed, Kind::Registry, &id, &dek, drawn()?)
            .map_err(|e| e.to_string())?;
        w[0] = 2;
        assert_eq!(
            unwrap(&m, Layer::Sealed, Kind::Registry, &id, &w).err(),
            Some(SealError::Header),
            "an envelope format this build does not read"
        );
        Ok(())
    }

    #[test]
    fn an_unknown_file_format_is_named() -> TestResult {
        let mut bytes = sealed(&key(1), &[], &[])?;
        bytes[4] = 9;
        let e = open_log(&bytes, &only(key(1)), Kind::Registry).err();
        assert_eq!(
            e,
            Some(SealError::UnknownFormat(9)),
            "the format byte is named"
        );
        Ok(())
    }

    #[test]
    fn modular_and_both_say_this_build_cannot_run_them() {
        for mode in [Encryption::Modular, Encryption::Both] {
            let why = mode.unavailable().unwrap_or_default();
            assert!(
                why.contains(&format!("--store-encryption {}", mode.as_str())),
                "{why}"
            );
            assert!(
                why.contains("sealed"),
                "it names the value that works: {why}"
            );
            assert!(!why.contains("  "), "one line, single spaces: {why}");
        }
    }

    #[test]
    fn a_record_over_the_bound_is_refused_when_sealing() -> TestResult {
        let source = counting();
        let (mut sealer, _) = LogSealer::new(&key(1), Kind::Registry, &source)?;
        let e = sealer
            .record(&vec![0u8; MAX_RECORD_BYTES + 1])
            .err()
            .unwrap_or_default();
        assert!(e.contains("8388608"), "{e}");
        Ok(())
    }

    #[test]
    fn a_length_over_the_bound_is_refused_when_reading() -> TestResult {
        let mut bytes = sealed(&key(1), &[b"r"], &[])?;
        bytes[HEADER_BYTES..HEADER_BYTES + 4].copy_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(
            open_log(&bytes, &only(key(1)), Kind::Registry).err(),
            Some(SealError::Record(1)),
            "a length no record can have"
        );
        Ok(())
    }

    #[test]
    fn no_message_or_debug_output_holds_the_key() {
        let k = key(0x41);
        let text = k.encode();
        let shown = format!("{k:?} {:?}", only(key(0x41)));
        assert!(!shown.contains(text.trim()), "{shown}");
        assert!(
            shown.contains(&k.id().to_string()),
            "it shows the id: {shown}"
        );
    }

    // ---- edge ----

    #[test]
    fn a_torn_record_after_the_base_is_dropped_and_reported() -> TestResult {
        let bytes = sealed(&key(1), &[b"base"], &[b"whole", b"torn-record"])?;
        let cut = &bytes[..bytes.len() - 5];
        let log = open_log(cut, &only(key(1)), Kind::Registry).map_err(|e| e.to_string())?;
        assert_eq!(
            log.records,
            vec![b"base".to_vec(), b"whole".to_vec()],
            "the records before the torn one"
        );
        assert!(log.torn_tail, "the torn record is reported");
        Ok(())
    }

    #[test]
    fn a_torn_length_after_the_base_is_dropped_and_reported() -> TestResult {
        let mut bytes = sealed(&key(1), &[b"base"], &[])?;
        bytes.extend([0, 0]);
        let log = open_log(&bytes, &only(key(1)), Kind::Registry).map_err(|e| e.to_string())?;
        assert_eq!(log.records, vec![b"base".to_vec()], "the base record");
        assert!(log.torn_tail, "the torn length is reported");
        Ok(())
    }

    #[test]
    fn a_whole_appended_record_that_fails_is_refused_not_dropped() -> TestResult {
        let mut bytes = sealed(&key(1), &[b"base"], &[b"appended"])?;
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        assert_eq!(
            open_log(&bytes, &only(key(1)), Kind::Registry).err(),
            Some(SealError::Record(3)),
            "the base end is record 2"
        );
        Ok(())
    }

    #[test]
    fn an_empty_record_round_trips() -> TestResult {
        let bytes = sealed(&key(1), &[b"", b"x"], &[b""])?;
        let log = open_log(&bytes, &only(key(1)), Kind::Registry).map_err(|e| e.to_string())?;
        assert_eq!(
            log.records,
            vec![Vec::new(), b"x".to_vec(), Vec::new()],
            "empty records are records"
        );
        Ok(())
    }

    #[test]
    fn a_record_at_the_bound_round_trips() -> TestResult {
        let big = vec![0xa5u8; MAX_RECORD_BYTES];
        let bytes = sealed(&key(1), &[&big], &[])?;
        let log = open_log(&bytes, &only(key(1)), Kind::Registry).map_err(|e| e.to_string())?;
        assert_eq!(log.records.len(), 1, "one record");
        assert_eq!(log.records[0], big, "the record is returned whole");
        Ok(())
    }

    #[test]
    fn bytes_that_are_not_sealed_say_so() {
        let keys = only(key(1));
        for plain in [&b""[..], b"{\"member\":\"edge-a\"}\n", b"SNF", b"snfs....."] {
            assert_eq!(
                open_log(plain, &keys, Kind::Registry).err(),
                Some(SealError::NotSealed),
                "no magic, so not a sealed file"
            );
        }
    }

    #[test]
    fn a_header_alone_is_truncated() -> TestResult {
        let bytes = sealed(&key(1), &[], &[])?;
        assert_eq!(
            open_log(&bytes[..HEADER_BYTES], &only(key(1)), Kind::Registry).err(),
            Some(SealError::Truncated),
            "a header with no base end after it"
        );
        Ok(())
    }

    #[test]
    fn a_header_cut_short_is_truncated() -> TestResult {
        let bytes = sealed(&key(1), &[], &[])?;
        for len in [4, 5, 6, 14, HEADER_BYTES - 1] {
            assert_eq!(
                open_log(&bytes[..len], &only(key(1)), Kind::Registry).err(),
                Some(SealError::Truncated),
                "{len} bytes"
            );
        }
        Ok(())
    }

    #[test]
    fn white_space_around_a_key_is_ignored() -> TestResult {
        let text = key(4).encode();
        let padded = format!("  \r\n{}\r\n\t", text.trim());
        assert_eq!(
            MasterKey::parse(&padded)?.id(),
            key(4).id(),
            "white space is not part of the key"
        );
        Ok(())
    }

    #[test]
    fn an_empty_key_file_is_refused_as_empty() {
        let e = MasterKey::parse(" \n").err().unwrap_or_default();
        assert!(e.contains("0 bytes"), "{e}");
    }

    #[test]
    fn keys_one_bit_apart_have_different_ids() {
        let mut bytes = [7u8; KEY_BYTES];
        let a = MasterKey::from_bytes(bytes).id();
        bytes[KEY_BYTES - 1] ^= 1;
        assert_ne!(
            a,
            MasterKey::from_bytes(bytes).id(),
            "one changed bit changes the id"
        );
    }

    #[test]
    fn the_current_key_is_found_before_an_old_one_and_a_stranger_is_not() {
        let keys = Keys::new(key(2), vec![key(1), key(3)]);
        assert_eq!(
            keys.find(key(2).id()).map(MasterKey::id),
            Some(key(2).id()),
            "the current key by its id"
        );
        assert_eq!(
            keys.find(key(3).id()).map(MasterKey::id),
            Some(key(3).id()),
            "an old key by its id"
        );
        assert!(
            keys.find(key(9).id()).is_none(),
            "a key that was never loaded"
        );
        assert_eq!(
            keys.current().id(),
            key(2).id(),
            "the current key is the first given"
        );
    }

    #[test]
    fn record_positions_never_share_a_nonce() {
        let seen: std::collections::BTreeSet<[u8; NONCE_BYTES]> = [
            0,
            1,
            2,
            u64::from(u32::MAX),
            u64::from(u32::MAX) + 1,
            u64::MAX,
        ]
        .into_iter()
        .map(position_nonce)
        .collect();
        assert_eq!(seen.len(), 6, "six positions, six nonces");
    }

    #[test]
    fn the_same_record_twice_seals_to_different_bytes() -> TestResult {
        let source = counting();
        let (mut sealer, _) = LogSealer::new(&key(1), Kind::Registry, &source)?;
        assert_ne!(
            sealer.record(b"same")?,
            sealer.record(b"same")?,
            "a position is used once, so the bytes differ"
        );
        Ok(())
    }

    #[test]
    fn a_base_end_moved_earlier_is_refused() -> TestResult {
        // The base end says how many records came before it, so cutting
        // records out and keeping the end does not pass.
        let source = counting();
        let (mut sealer, header) = LogSealer::new(&key(1), Kind::Registry, &source)?;
        let _dropped = sealer.record(b"gone")?;
        let end = sealer.base_end()?;
        let mut bytes = header.to_vec();
        bytes.extend(end);
        assert_eq!(
            open_log(&bytes, &only(key(1)), Kind::Registry).err(),
            Some(SealError::Record(1)),
            "the base end was sealed for position 1, not 0"
        );
        Ok(())
    }

    #[test]
    fn a_base_end_that_counts_wrong_is_refused() -> TestResult {
        // Sealed with the real key at its real position, so only the count
        // it carries is wrong: one record came before it, and it says two.
        let source = counting();
        let (mut sealer, header) = LogSealer::new(&key(1), Kind::Registry, &source)?;
        let mut bytes = header.to_vec();
        bytes.extend(sealer.record(b"one")?);
        bytes.extend(sealer.frame(FRAME_BASE_END, &2u64.to_be_bytes())?);
        assert_eq!(
            open_log(&bytes, &only(key(1)), Kind::Registry).err(),
            Some(SealError::Record(2)),
            "the base end is record 2, and its count is not the records before it"
        );
        Ok(())
    }

    #[test]
    fn a_second_base_end_is_refused() -> TestResult {
        let source = counting();
        let (mut sealer, header) = LogSealer::new(&key(1), Kind::Registry, &source)?;
        let mut bytes = header.to_vec();
        bytes.extend(sealer.base_end()?);
        bytes.extend(sealer.base_end()?);
        assert_eq!(
            open_log(&bytes, &only(key(1)), Kind::Registry).err(),
            Some(SealError::Record(2)),
            "a file has one base"
        );
        Ok(())
    }

    #[test]
    fn a_record_of_an_unknown_type_is_refused() -> TestResult {
        let source = counting();
        let (mut sealer, header) = LogSealer::new(&key(1), Kind::Registry, &source)?;
        let mut bytes = header.to_vec();
        bytes.extend(sealer.frame(9, b"what")?);
        bytes.extend(sealer.base_end()?);
        assert_eq!(
            open_log(&bytes, &only(key(1)), Kind::Registry).err(),
            Some(SealError::Record(1)),
            "a type byte this build does not read"
        );
        Ok(())
    }

    // ---- the count slots (format 2): records removed from the end ----

    /// Ends an append in `bytes` and writes `sealer`'s next count slot, as
    /// an append does once its records are on disk. Returns where the slot
    /// is.
    fn count(bytes: &mut Vec<u8>, sealer: &mut LogSealer) -> Result<usize, String> {
        bytes.extend(sealer.append_end()?);
        let (at, slot) = sealer.count_slot()?;
        bytes
            .get_mut(at..at + COUNT_SLOT_BYTES)
            .ok_or("the slot is outside the file")?
            .copy_from_slice(&slot);
        Ok(at)
    }

    /// A registry file with one base record and `appended` after it, each
    /// append counted as the center counts it; and the offset each record
    /// of `appended` starts at.
    fn counted(appended: &[&[u8]]) -> Result<(Vec<u8>, Vec<usize>), String> {
        let source = counting();
        let (mut sealer, header) = LogSealer::new(&key(1), Kind::Registry, &source)?;
        let mut out = header.to_vec();
        out.extend(sealer.record(b"base")?);
        out.extend(sealer.base_end()?);
        let mut starts = Vec::new();
        for r in appended {
            starts.push(out.len());
            out.extend(sealer.record(r)?);
            count(&mut out, &mut sealer)?;
        }
        Ok((out, starts))
    }

    /// A format 1 registry file, written the way the releases before the
    /// count slots wrote it: the key header, then the records.
    fn sealed_v1(records: &[&[u8]], appended: &[&[u8]]) -> Result<Vec<u8>, String> {
        sealed_format_1(Kind::Registry, &key(1), records, appended, &counting())
    }

    #[test]
    fn success_a_counted_file_returns_every_record() -> TestResult {
        let (bytes, _) = counted(&[b"one", b"two"])?;
        let log = open_log(&bytes, &only(key(1)), Kind::Registry).map_err(|e| e.to_string())?;
        assert_eq!(
            log.records,
            vec![b"base".to_vec(), b"one".to_vec(), b"two".to_vec()],
            "success a counted file returns every record"
        );
        assert!(!log.torn_tail, "and nothing in it is torn");
        Ok(())
    }

    #[test]
    fn success_this_build_writes_format_2_with_two_count_slots() -> TestResult {
        let (bytes, starts) = counted(&[b"one"])?;
        assert_eq!(bytes[4], 2, "the format byte");
        assert_eq!(FORMAT, 2, "the format this build writes");
        assert_eq!(
            HEADER_BYTES,
            KEY_HEADER_BYTES + 2 * COUNT_SLOT_BYTES,
            "the header ends after two count slots"
        );
        assert_eq!(COUNT_SLOT_BYTES, 8 + 16, "a slot is a count and a tag");
        assert!(
            starts[0] > HEADER_BYTES,
            "the appended record is after the base, which is after the header"
        );
        Ok(())
    }

    #[test]
    fn success_a_format_1_file_still_opens() -> TestResult {
        let bytes = sealed_v1(&[b"base"], &[b"kept"])?;
        assert_eq!(bytes[4], 1, "the fixture is a format 1 file");
        let log = open_log(&bytes, &only(key(1)), Kind::Registry).map_err(|e| e.to_string())?;
        assert_eq!(
            log.records,
            vec![b"base".to_vec(), b"kept".to_vec()],
            "success a format 1 file still opens"
        );
        Ok(())
    }

    #[test]
    fn success_a_count_slot_holds_the_frames_sealed_so_far() -> TestResult {
        let source = counting();
        let (mut sealer, header) = LogSealer::new(&key(1), Kind::Registry, &source)?;
        let mut out = header.to_vec();
        out.extend(sealer.record(b"base")?);
        out.extend(sealer.base_end()?);
        out.extend(sealer.record(b"one")?);
        assert_eq!(
            sealer.counted(),
            0,
            "nothing is counted before the first slot"
        );
        count(&mut out, &mut sealer)?;
        assert_eq!(
            sealer.counted(),
            4,
            "success a count slot holds the frames sealed so far"
        );
        Ok(())
    }

    #[test]
    fn failure_a_whole_appended_record_removed_from_the_end_is_refused() -> TestResult {
        // The defect FLEET-STORE-TAIL-TRUNCATION: before the count slots
        // this file opened without its last record and nothing marked it.
        let (bytes, starts) = counted(&[b"kept", b"removed"])?;
        let cut = &bytes[..starts[1]];
        assert_eq!(
            open_log(cut, &only(key(1)), Kind::Registry).err(),
            Some(SealError::Cut {
                held: 4,
                counted: 6
            }),
            "failure a whole appended record removed from the end is refused"
        );
        Ok(())
    }

    #[test]
    fn failure_every_appended_record_removed_is_refused() -> TestResult {
        let (bytes, starts) = counted(&[b"one", b"two", b"three"])?;
        let cut = &bytes[..starts[0]];
        assert_eq!(
            open_log(cut, &only(key(1)), Kind::Registry).err(),
            Some(SealError::Cut {
                held: 2,
                counted: 8
            }),
            "failure every appended record removed is refused"
        );
        Ok(())
    }

    #[test]
    fn failure_a_counted_record_cut_in_its_middle_is_refused_not_dropped() -> TestResult {
        // A record the count covers was synced whole before it was counted,
        // so a part of it is a cut and never an unfinished write.
        let (bytes, starts) = counted(&[b"one", b"two"])?;
        let cut = &bytes[..starts[1] + 7];
        assert_eq!(
            open_log(cut, &only(key(1)), Kind::Registry).err(),
            Some(SealError::Cut {
                held: 4,
                counted: 6
            }),
            "failure a counted record cut in its middle is refused not dropped"
        );
        Ok(())
    }

    #[test]
    fn failure_a_file_with_no_count_slot_that_authenticates_is_refused() -> TestResult {
        let (mut bytes, _) = counted(&[b"one"])?;
        bytes[KEY_HEADER_BYTES] ^= 1;
        bytes[KEY_HEADER_BYTES + COUNT_SLOT_BYTES] ^= 1;
        assert_eq!(
            open_log(&bytes, &only(key(1)), Kind::Registry).err(),
            Some(SealError::Count),
            "failure a file with no count slot that authenticates is refused"
        );
        Ok(())
    }

    #[test]
    fn failure_count_slots_zeroed_to_hide_a_cut_are_refused() -> TestResult {
        let (mut bytes, starts) = counted(&[b"one", b"two"])?;
        bytes[KEY_HEADER_BYTES..HEADER_BYTES].fill(0);
        bytes.truncate(starts[1]);
        assert_eq!(
            open_log(&bytes, &only(key(1)), Kind::Registry).err(),
            Some(SealError::Count),
            "failure count slots zeroed to hide a cut are refused"
        );
        Ok(())
    }

    #[test]
    fn failure_the_count_slots_of_another_file_are_refused() -> TestResult {
        let (mut bytes, _) = counted(&[b"one"])?;
        // Another file under the same master key: its own id and data key.
        let source = counting();
        let _ = LogSealer::new(&key(1), Kind::Registry, &source)?;
        let (mut other, other_header) = LogSealer::new(&key(1), Kind::Registry, &source)?;
        let mut other_bytes = other_header.to_vec();
        other_bytes.extend(other.record(b"x")?);
        count(&mut other_bytes, &mut other)?;
        bytes[KEY_HEADER_BYTES..HEADER_BYTES]
            .copy_from_slice(&other_bytes[KEY_HEADER_BYTES..HEADER_BYTES]);
        assert_eq!(
            open_log(&bytes, &only(key(1)), Kind::Registry).err(),
            Some(SealError::Count),
            "failure the count slots of another file are refused"
        );
        Ok(())
    }

    #[test]
    fn failure_a_format_2_file_marked_format_1_is_refused() -> TestResult {
        let (mut bytes, _) = counted(&[b"one"])?;
        bytes[4] = 1;
        assert!(
            matches!(
                open_log(&bytes, &only(key(1)), Kind::Registry),
                Err(SealError::Record(_) | SealError::Truncated)
            ),
            "failure a format 2 file marked format 1 is refused"
        );
        Ok(())
    }

    #[test]
    fn failure_a_format_1_file_marked_format_2_is_refused() -> TestResult {
        let mut bytes = sealed_v1(&[b"base"], &[b"kept"])?;
        bytes[4] = 2;
        assert!(
            open_log(&bytes, &only(key(1)), Kind::Registry).is_err(),
            "failure a format 1 file marked format 2 is refused"
        );
        Ok(())
    }

    #[test]
    fn failure_format_1_records_behind_a_format_2_header_are_refused() -> TestResult {
        // The records of a format 1 file are bound to format 1: placed
        // after valid count slots of the same file id they do not open.
        let v1 = sealed_v1(&[b"base"], &[])?;
        let source = counting();
        let (_, header) = LogSealer::new(&key(1), Kind::Registry, &source)?;
        assert_eq!(
            header[..KEY_HEADER_BYTES][5..],
            v1[..KEY_HEADER_BYTES][5..],
            "the two files share an id and a data key"
        );
        let mut bytes = header.to_vec();
        bytes.extend(&v1[KEY_HEADER_BYTES..]);
        assert_eq!(
            open_log(&bytes, &only(key(1)), Kind::Registry).err(),
            Some(SealError::Record(1)),
            "failure format 1 records behind a format 2 header are refused"
        );
        Ok(())
    }

    #[test]
    fn edge_records_synced_but_not_yet_counted_open() -> TestResult {
        // A crash between the sync of an append and the write of its
        // count: the file holds more than its count says, which is no cut.
        let source = counting();
        let (mut sealer, header) = LogSealer::new(&key(1), Kind::Registry, &source)?;
        let mut out = header.to_vec();
        out.extend(sealer.record(b"base")?);
        out.extend(sealer.base_end()?);
        out.extend(sealer.record(b"one")?);
        count(&mut out, &mut sealer)?;
        out.extend(sealer.record(b"two")?);
        let log = open_log(&out, &only(key(1)), Kind::Registry).map_err(|e| e.to_string())?;
        assert_eq!(
            log.records.len(),
            3,
            "edge records synced but not yet counted open"
        );
        Ok(())
    }

    #[test]
    fn edge_a_torn_count_slot_leaves_the_older_count_in_force() -> TestResult {
        // A crash while a slot was being written: that slot does not
        // authenticate, and the other still holds the count before it.
        let source = counting();
        let (mut sealer, header) = LogSealer::new(&key(1), Kind::Registry, &source)?;
        let mut out = header.to_vec();
        out.extend(sealer.record(b"base")?);
        out.extend(sealer.base_end()?);
        out.extend(sealer.record(b"one")?);
        count(&mut out, &mut sealer)?;
        let second = out.len();
        out.extend(sealer.record(b"two")?);
        let torn = count(&mut out, &mut sealer)?;
        out[torn + 3] ^= 0x40;
        let log = open_log(&out, &only(key(1)), Kind::Registry).map_err(|e| e.to_string())?;
        assert_eq!(log.records.len(), 3, "the file opens whole");
        // The older count still refuses a cut below it.
        assert_eq!(
            open_log(&out[..second - 1], &only(key(1)), Kind::Registry).err(),
            Some(SealError::Cut {
                held: 3,
                counted: 4
            }),
            "edge a torn count slot leaves the older count in force"
        );
        Ok(())
    }

    #[test]
    fn edge_count_slots_alternate_so_one_always_holds_an_older_count() -> TestResult {
        let source = counting();
        let (mut sealer, header) = LogSealer::new(&key(1), Kind::Registry, &source)?;
        let mut out = header.to_vec();
        out.extend(sealer.base_end()?);
        let mut places = Vec::new();
        for r in [b"a", b"b", b"c", b"d"] {
            out.extend(sealer.record(r)?);
            places.push(count(&mut out, &mut sealer)?);
        }
        assert_eq!(
            places,
            vec![
                KEY_HEADER_BYTES + COUNT_SLOT_BYTES,
                KEY_HEADER_BYTES,
                KEY_HEADER_BYTES + COUNT_SLOT_BYTES,
                KEY_HEADER_BYTES
            ],
            "edge count slots alternate so one always holds an older count"
        );
        Ok(())
    }

    #[test]
    fn edge_a_new_file_with_no_records_opens_and_counts_nothing() -> TestResult {
        let source = counting();
        let (mut sealer, header) = LogSealer::new(&key(1), Kind::Registry, &source)?;
        let mut out = header.to_vec();
        out.extend(sealer.base_end()?);
        let log = open_log(&out, &only(key(1)), Kind::Registry).map_err(|e| e.to_string())?;
        assert!(
            log.records.is_empty(),
            "edge a new file with no records opens and counts nothing"
        );
        assert_eq!(sealer.counted(), 0, "its slots count no frame");
        Ok(())
    }

    #[test]
    fn edge_an_unfinished_append_after_the_count_is_still_a_torn_tail() -> TestResult {
        let (mut bytes, _) = counted(&[b"one"])?;
        bytes.extend([0, 0, 0, 40, 9, 9, 9]);
        let log = open_log(&bytes, &only(key(1)), Kind::Registry).map_err(|e| e.to_string())?;
        assert!(
            log.torn_tail,
            "edge an unfinished append after the count is still a torn tail"
        );
        assert_eq!(
            log.records.len(),
            2,
            "and the counted records are all there"
        );
        Ok(())
    }

    #[test]
    fn edge_a_format_1_file_cut_at_its_end_still_opens_the_known_limit() -> TestResult {
        // Format 1 has no count. A file a release before the count slots
        // wrote opens once more without its last appended record; the
        // open rewrites it as format 2.
        let bytes = sealed_v1(&[b"base"], &[b"kept", b"removed"])?;
        let last = 4 + 1 + b"removed".len() + TAG_BYTES;
        let log = open_log(&bytes[..bytes.len() - last], &only(key(1)), Kind::Registry)
            .map_err(|e| e.to_string())?;
        assert_eq!(
            log.records.len(),
            2,
            "edge a format 1 file cut at its end still opens the known limit"
        );
        Ok(())
    }

    /// A new sealed registry file at `path` with an empty base, and its
    /// sealer.
    fn new_file(path: &Path) -> Result<LogSealer, Box<dyn std::error::Error>> {
        let source = counting();
        let (mut sealer, header) = LogSealer::new(&key(1), Kind::Registry, &source)?;
        let mut out = header.to_vec();
        out.extend(sealer.base_end()?);
        std::fs::write(path, out)?;
        Ok(sealer)
    }

    #[test]
    fn success_an_append_puts_its_records_and_then_their_count_on_disk() -> TestResult {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("log");
        let mut sealer = new_file(&path)?;
        let frames = [sealer.record(b"one")?, sealer.record(b"two")?].concat();
        append_counted(&path, &mut sealer, &frames)?;
        let bytes = std::fs::read(&path)?;
        let log = open_log(&bytes, &only(key(1)), Kind::Registry).map_err(|e| e.to_string())?;
        assert_eq!(
            log.records,
            vec![b"one".to_vec(), b"two".to_vec()],
            "success an append puts its records and then their count on disk"
        );
        assert_eq!(
            sealer.counted(),
            4,
            "the end of the base, two records, the end of the append"
        );
        Ok(())
    }

    #[test]
    fn failure_a_file_cut_after_an_append_is_refused_when_read_from_disk() -> TestResult {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("log");
        let mut sealer = new_file(&path)?;
        let first = sealer.record(b"one")?;
        append_counted(&path, &mut sealer, &first)?;
        let kept = std::fs::metadata(&path)?.len();
        let second = sealer.record(b"two")?;
        append_counted(&path, &mut sealer, &second)?;
        let bytes = std::fs::read(&path)?;
        let cut = &bytes[..usize::try_from(kept)?];
        assert_eq!(
            open_log(cut, &only(key(1)), Kind::Registry).err(),
            Some(SealError::Cut {
                held: 3,
                counted: 5
            }),
            "failure a file cut after an append is refused when read from disk"
        );
        Ok(())
    }

    #[test]
    fn failure_an_append_to_a_file_that_is_gone_fails_and_counts_nothing() -> TestResult {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("log");
        let mut sealer = new_file(&path)?;
        std::fs::remove_file(&path)?;
        let frames = sealer.record(b"one")?;
        let e = append_counted(&path, &mut sealer, &frames).err();
        assert_eq!(
            e.map(|e| e.kind()),
            Some(std::io::ErrorKind::NotFound),
            "failure an append to a file that is gone fails and counts nothing"
        );
        assert_eq!(sealer.counted(), 0, "no count was made");
        assert!(!path.exists(), "and the append did not create the file");
        Ok(())
    }

    #[test]
    fn edge_an_append_writes_after_the_end_and_changes_no_earlier_record() -> TestResult {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("log");
        let mut sealer = new_file(&path)?;
        let first = sealer.record(b"one")?;
        append_counted(&path, &mut sealer, &first)?;
        let before = std::fs::read(&path)?;
        let second = sealer.record(b"two")?;
        append_counted(&path, &mut sealer, &second)?;
        let after = std::fs::read(&path)?;
        assert_eq!(
            after[HEADER_BYTES..before.len()],
            before[HEADER_BYTES..],
            "edge an append writes after the end and changes no earlier record"
        );
        assert_eq!(
            after.len(),
            before.len() + second.len() + 4 + 1 + TAG_BYTES,
            "it grew by the record and the end of the append"
        );
        assert_eq!(
            after[..KEY_HEADER_BYTES],
            before[..KEY_HEADER_BYTES],
            "and the key header is as it was"
        );
        Ok(())
    }

    #[test]
    fn the_cut_refusal_says_what_is_missing() {
        assert_eq!(
            SealError::Cut {
                held: 3,
                counted: 4
            }
            .to_string(),
            "was cut at its end: it holds 3 of the 4 entries it was written with",
            "the cut refusal says what is missing"
        );
        assert_eq!(
            SealError::Count.to_string(),
            "has a record count that did not authenticate (the file was modified, or the key \
             is wrong)",
            "the count refusal says what failed"
        );
    }

    /// One append of `records` to a file with an empty base, as the center
    /// writes it; then the count before it, and where the append starts.
    fn one_append(records: &[&[u8]]) -> Result<(Vec<u8>, usize, Vec<usize>), String> {
        let source = counting();
        let (mut sealer, header) = LogSealer::new(&key(1), Kind::Intake, &source)?;
        let mut out = header.to_vec();
        out.extend(sealer.base_end()?);
        out.extend(sealer.record(b"first")?);
        count(&mut out, &mut sealer)?;
        let mut starts = Vec::new();
        for r in records {
            starts.push(out.len());
            out.extend(sealer.record(r)?);
        }
        let newest = count(&mut out, &mut sealer)?;
        Ok((out, newest, starts))
    }

    #[test]
    fn failure_a_damaged_newest_count_does_not_hide_the_last_append_removed() -> TestResult {
        // The attack a torn count would allow: damage the newest count so
        // the older one is in force, and remove the append it covered.
        let (mut bytes, newest, starts) = one_append(&[b"a", b"b"])?;
        bytes[newest + 9] ^= 1;
        bytes.truncate(starts[0]);
        assert_eq!(
            open_log(&bytes, &only(key(1)), Kind::Intake).err(),
            Some(SealError::Count),
            "failure a damaged newest count does not hide the last append removed"
        );
        Ok(())
    }

    #[test]
    fn failure_a_damaged_newest_count_does_not_hide_a_part_of_the_last_append_removed() -> TestResult
    {
        // The same attack on an append of several records, cut between two
        // of them: the file holds more than the older count, and does not
        // end where an append ends.
        let (mut bytes, newest, starts) = one_append(&[b"a", b"b", b"c"])?;
        bytes[newest + 9] ^= 1;
        bytes.truncate(starts[2]);
        assert_eq!(
            open_log(&bytes, &only(key(1)), Kind::Intake).err(),
            Some(SealError::Count),
            "failure a damaged newest count does not hide a part of the last append removed"
        );
        Ok(())
    }

    #[test]
    fn failure_a_damaged_count_with_a_torn_record_after_it_is_refused() -> TestResult {
        // A count is written only after its append is on disk whole, so a
        // count that did not finish never comes with a part of a record.
        let (mut bytes, newest, starts) = one_append(&[b"a", b"b"])?;
        bytes[newest + 9] ^= 1;
        bytes.truncate(starts[1] + 6);
        assert_eq!(
            open_log(&bytes, &only(key(1)), Kind::Intake).err(),
            Some(SealError::Count),
            "failure a damaged count with a torn record after it is refused"
        );
        Ok(())
    }

    #[test]
    fn failure_a_damaged_older_count_on_a_whole_file_is_refused() -> TestResult {
        // No crash leaves this: the older slot is rewritten only after a
        // newer append is on disk, and here there is none.
        let (mut bytes, newest, _) = one_append(&[b"a"])?;
        let older = if newest == KEY_HEADER_BYTES {
            KEY_HEADER_BYTES + COUNT_SLOT_BYTES
        } else {
            KEY_HEADER_BYTES
        };
        bytes[older + 9] ^= 1;
        assert_eq!(
            open_log(&bytes, &only(key(1)), Kind::Intake).err(),
            Some(SealError::Count),
            "failure a damaged older count on a whole file is refused"
        );
        Ok(())
    }

    #[test]
    fn failure_the_two_count_slots_exchanged_are_refused() -> TestResult {
        let (mut bytes, _, _) = one_append(&[b"a"])?;
        let (a, b) = (KEY_HEADER_BYTES, KEY_HEADER_BYTES + COUNT_SLOT_BYTES);
        let first: Vec<u8> = bytes[a..b].to_vec();
        bytes.copy_within(b..HEADER_BYTES, a);
        bytes[b..HEADER_BYTES].copy_from_slice(&first);
        assert_eq!(
            open_log(&bytes, &only(key(1)), Kind::Intake).err(),
            Some(SealError::Count),
            "failure the two count slots exchanged are refused"
        );
        Ok(())
    }

    #[test]
    fn failure_a_damaged_count_with_a_part_of_a_record_after_a_whole_append_is_refused()
    -> TestResult {
        // The next append starts only after a count is written, so a count
        // that did not finish never has anything after its append: not
        // even a part of a record.
        let (mut bytes, newest, _) = one_append(&[b"a"])?;
        bytes[newest + 9] ^= 1;
        bytes.extend([0, 0, 0, 30, 4, 4, 4]);
        assert_eq!(
            open_log(&bytes, &only(key(1)), Kind::Intake).err(),
            Some(SealError::Count),
            "failure a damaged count with a part of a record after a whole append is refused"
        );
        Ok(())
    }

    #[test]
    fn failure_counts_lowered_to_hide_a_cut_are_refused() -> TestResult {
        // The count is written in clear beside its tag. A lower number in
        // its place does not authenticate, in either slot.
        let (mut bytes, starts) = counted(&[b"one", b"two"])?;
        for slot in 0..2 {
            let at = KEY_HEADER_BYTES + slot * COUNT_SLOT_BYTES;
            bytes[at..at + 8].copy_from_slice(&4u64.to_be_bytes());
        }
        bytes.truncate(starts[1]);
        assert_eq!(
            open_log(&bytes, &only(key(1)), Kind::Registry).err(),
            Some(SealError::Count),
            "failure counts lowered to hide a cut are refused"
        );
        Ok(())
    }

    #[test]
    fn failure_one_count_lowered_does_not_hide_a_cut() -> TestResult {
        // Only the newest count lowered: the other slot still authenticates
        // with its older count, and the file is not in the state a crash
        // leaves.
        let (mut bytes, starts) = counted(&[b"one", b"two"])?;
        // `counted` writes slot 1, then slot 0: slot 0 is the newest.
        bytes[KEY_HEADER_BYTES..KEY_HEADER_BYTES + 8].copy_from_slice(&4u64.to_be_bytes());
        bytes.truncate(starts[1]);
        assert_eq!(
            open_log(&bytes, &only(key(1)), Kind::Registry).err(),
            Some(SealError::Count),
            "failure one count lowered does not hide a cut"
        );
        Ok(())
    }

    #[test]
    fn failure_an_append_end_that_carries_bytes_is_refused() -> TestResult {
        // No writer makes one; a reader that took it would take bytes no
        // rule gives a meaning to.
        let source = counting();
        let (mut sealer, header) = LogSealer::new(&key(1), Kind::Registry, &source)?;
        let mut bytes = header.to_vec();
        bytes.extend(sealer.base_end()?);
        bytes.extend(sealer.record(b"one")?);
        bytes.extend(sealer.frame(FRAME_APPEND_END, b"x")?);
        assert_eq!(
            open_log(&bytes, &only(key(1)), Kind::Registry).err(),
            Some(SealError::Record(3)),
            "failure an append end that carries bytes is refused"
        );
        Ok(())
    }

    #[test]
    fn edge_a_count_that_did_not_finish_leaves_a_file_that_opens_whole() -> TestResult {
        // The crash itself: the append is on disk, its count is not.
        let (mut bytes, newest, _) = one_append(&[b"a", b"b"])?;
        bytes[newest..newest + COUNT_SLOT_BYTES].fill(0);
        let log = open_log(&bytes, &only(key(1)), Kind::Intake).map_err(|e| e.to_string())?;
        assert_eq!(
            log.records,
            vec![b"first".to_vec(), b"a".to_vec(), b"b".to_vec()],
            "edge a count that did not finish leaves a file that opens whole"
        );
        assert!(!log.torn_tail, "and nothing in it is torn");
        Ok(())
    }

    #[test]
    fn success_a_file_of_every_kind_carries_its_counts_and_opens() -> TestResult {
        for kind in [Kind::Registry, Kind::Intake, Kind::Spool, Kind::Calls] {
            let source = counting();
            let (mut sealer, header) = LogSealer::new(&key(1), kind, &source)?;
            let mut out = header.to_vec();
            out.extend(sealer.base_end()?);
            out.extend(sealer.record(b"one")?);
            count(&mut out, &mut sealer)?;
            let log = open_log(&out, &only(key(1)), kind).map_err(|e| e.to_string())?;
            assert_eq!(
                log.records,
                vec![b"one".to_vec()],
                "success a file of every kind carries its counts and opens: {}",
                kind.name()
            );
        }
        Ok(())
    }

    #[test]
    fn success_a_counted_file_opens_under_an_old_key() -> TestResult {
        let (bytes, _) = counted(&[b"one"])?;
        let keys = Keys::new(key(9), vec![key(1)]);
        let log = open_log(&bytes, &keys, Kind::Registry).map_err(|e| e.to_string())?;
        assert_eq!(
            log.records.len(),
            2,
            "success a counted file opens under an old key"
        );
        assert_eq!(log.key_id, key(1).id(), "and says which key it was");
        Ok(())
    }

    #[test]
    fn success_fifty_appends_on_disk_all_read_back_in_order() -> TestResult {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("log");
        let mut sealer = new_file(&path)?;
        let wanted: Vec<Vec<u8>> = (0..50u8).map(|n| vec![n; usize::from(n) + 1]).collect();
        for record in &wanted {
            let frame = sealer.record(record)?;
            append_counted(&path, &mut sealer, &frame)?;
        }
        let bytes = std::fs::read(&path)?;
        let log = open_log(&bytes, &only(key(1)), Kind::Registry).map_err(|e| e.to_string())?;
        assert_eq!(
            log.records, wanted,
            "success fifty appends on disk all read back in order"
        );
        assert_eq!(
            sealer.counted(),
            101,
            "a base end, and a record and an end each"
        );
        Ok(())
    }

    #[test]
    fn edge_an_append_of_nothing_writes_nothing_and_counts_nothing() -> TestResult {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("log");
        let mut sealer = new_file(&path)?;
        let before = std::fs::read(&path)?;
        append_counted(&path, &mut sealer, &[])?;
        assert_eq!(
            std::fs::read(&path)?,
            before,
            "edge an append of nothing writes nothing and counts nothing"
        );
        assert_eq!(sealer.counted(), 0, "no count was made");
        Ok(())
    }

    #[test]
    fn failure_an_append_end_in_a_format_1_file_is_refused() -> TestResult {
        // Format 1 never held one. This one is sealed as a format 1 entry
        // would be, with the file's own data key, and is refused for what
        // it is.
        let mut bytes = sealed_v1(&[b"base"], &[])?;
        // `sealed_v1` draws the file id and then the data key from
        // `counting`; the same draws give the same two values.
        let source = counting();
        let file_id = *draw::<FILE_ID_BYTES>(&source)?;
        let data_key = draw::<KEY_BYTES>(&source)?;
        let mut body = vec![FRAME_APPEND_END];
        cipher(&data_key)
            .map_err(|e| e.to_string())?
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(position_nonce(2)),
                Aad::from(file_id),
                &mut body,
            )
            .map_err(|_| "seal")?;
        bytes.extend((body.len() as u32).to_be_bytes());
        bytes.extend(body);
        assert_eq!(
            open_log(&bytes, &only(key(1)), Kind::Registry).err(),
            Some(SealError::Record(3)),
            "failure an append end in a format 1 file is refused"
        );
        Ok(())
    }

    #[test]
    fn edge_an_append_end_is_no_record() -> TestResult {
        let (bytes, _, _) = one_append(&[b"a"])?;
        let log = open_log(&bytes, &only(key(1)), Kind::Intake).map_err(|e| e.to_string())?;
        assert_eq!(
            log.records.len(),
            2,
            "edge an append end is no record: two records, two ends, one base end"
        );
        Ok(())
    }

    /// A source that returns `given(asked)` bytes of 0xA5 whatever it is
    /// asked for.
    fn giving(given: fn(usize) -> usize) -> impl Fn(usize) -> Result<Zeroizing<Vec<u8>>, String> {
        move |asked: usize| Ok(Zeroizing::new(vec![0xA5; given(asked)]))
    }

    #[test]
    fn a_source_that_returns_nothing_is_an_error_and_never_a_zero_value() {
        let e = draw::<NONCE_BYTES>(&giving(|_| 0)).map(|nonce| *nonce);
        assert_eq!(
            e,
            Err("the random source returned 0 bytes where 12 were asked for".to_string()),
            "no nonce is made from a source that gave nothing"
        );
    }

    #[test]
    fn a_source_that_returns_fewer_bytes_than_asked_is_an_error() {
        let e = draw::<KEY_BYTES>(&giving(|asked| asked - 1)).map(|key| *key);
        assert_eq!(
            e,
            Err("the random source returned 31 bytes where 32 were asked for".to_string()),
            "no key is completed with bytes the source did not give"
        );
    }

    #[test]
    fn a_source_that_returns_more_bytes_than_asked_is_an_error() {
        let e = draw::<FILE_ID_BYTES>(&giving(|asked| asked + 1)).map(|id| *id);
        assert_eq!(
            e,
            Err("the random source returned 17 bytes where 16 were asked for".to_string()),
            "a source that does not do what it is asked is not used"
        );
    }

    #[test]
    fn a_new_file_is_refused_when_any_of_its_three_draws_comes_back_short() {
        // The draws of a new file, in order: file id, data key, wrap nonce.
        for short in 0..3 {
            let (calls, good) = (std::cell::Cell::new(0), counting());
            let source = |asked: usize| {
                if calls.replace(calls.get() + 1) == short {
                    good(asked - 1)
                } else {
                    good(asked)
                }
            };
            let e = LogSealer::new(&key(1), Kind::Registry, &source)
                .err()
                .unwrap_or_default();
            assert!(
                e.starts_with("the random source returned "),
                "draw {short} came back short and the file was still made: '{e}'"
            );
            assert_eq!(calls.get(), short + 1, "nothing is drawn after the refusal");
        }
    }

    #[test]
    fn keygen_refuses_a_source_that_returns_too_few_bytes_and_leaves_no_file() -> TestResult {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("store.key");
        let e = write_new_key_file(&path, &giving(|_| 0))
            .err()
            .unwrap_or_default();
        assert!(
            e.ends_with("the random source returned 0 bytes where 32 were asked for"),
            "{e}"
        );
        assert!(!path.exists(), "no file holding a key that was never drawn");
        Ok(())
    }

    #[test]
    fn the_system_source_returns_the_count_asked_for_across_its_block_size() -> TestResult {
        for len in [
            0,
            1,
            NONCE_BYTES,
            KEY_BYTES,
            KEY_BYTES + 1,
            2 * KEY_BYTES,
            100,
        ] {
            assert_eq!(system_draw(len)?.len(), len, "a draw of {len} bytes");
        }
        Ok(())
    }

    #[test]
    fn the_system_source_fills_and_two_draws_differ() -> TestResult {
        let (a, b) = (system_draw(32)?, system_draw(32)?);
        assert_eq!((a.len(), b.len()), (32, 32), "each draw has its length");
        assert_ne!(a, b, "two draws of 32 bytes are not equal");
        Ok(())
    }
}
