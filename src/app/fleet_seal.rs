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
//!   file's id as associated data. A file is
//!   never appended to by a later process: [`open_log`] reads, and the
//!   caller writes a new file under a new data key.
//!
//! # What is pure and what is not
//!
//! [`MasterKey::parse`], [`wrap`], [`unwrap`], [`LogSealer`] and
//! [`open_log`] work on bytes and take their randomness as an argument.
//! [`read_key_file`], [`write_new_key_file`] and [`system_fill`] are the
//! three functions that touch the file system or the system random source.

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

/// The sealed file format this build writes and reads.
pub const FORMAT: u8 = 1;

/// Bytes in an AES-GCM nonce.
const NONCE_BYTES: usize = 12;

/// Bytes in an AES-GCM tag.
const TAG_BYTES: usize = 16;

/// Bytes in a file id.
pub const FILE_ID_BYTES: usize = 16;

/// Bytes in a wrapped data key: format byte, nonce, key, tag.
pub const WRAPPED_BYTES: usize = 1 + NONCE_BYTES + KEY_BYTES + TAG_BYTES;

/// Bytes in a sealed file's header: magic, format, kind, key id, file id,
/// wrapped data key.
pub const HEADER_BYTES: usize = MAGIC.len() + 1 + 1 + 8 + FILE_ID_BYTES + WRAPPED_BYTES;

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

/// The label hashed before the key to give its id, so the id is no other
/// SHA-256 of the key.
const ID_DOMAIN: &[u8] = b"sipnab fleet store key id v1\0";

/// What a wrapped data key's associated data starts with.
const WRAP_DOMAIN: &[u8] = b"sipnab fleet store wrap v1\0";

/// Fills a buffer with random bytes, or says why it could not.
pub type Fill<'a> = &'a dyn Fn(&mut [u8]) -> Result<(), String>;

/// Fill `out` from the system random source.
///
/// # Errors
///
/// The source failed. There is no weaker fallback.
pub fn system_fill(out: &mut [u8]) -> Result<(), String> {
    use ring::rand::SecureRandom as _;
    ring::rand::SystemRandom::new()
        .fill(out)
        .map_err(|_| "the system random source failed".to_string())
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
}

impl Kind {
    /// The byte that names this kind in a header.
    const fn byte(self) -> u8 {
        match self {
            Self::Registry => 1,
            Self::Intake => 2,
        }
    }

    /// The name of this kind in a message.
    const fn name(self) -> &'static str {
        match self {
            Self::Registry => "registry",
            Self::Intake => "intake",
        }
    }

    /// The kind `byte` names, if any.
    const fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Self::Registry),
            2 => Some(Self::Intake),
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
fn record_aad(file_id: &[u8; FILE_ID_BYTES]) -> [u8; FILE_ID_BYTES] {
    *file_id
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
    out[0] = FORMAT;
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
    if wrapped[0] != FORMAT {
        return Err(SealError::Header);
    }
    let mut nonce = [0u8; NONCE_BYTES];
    nonce.copy_from_slice(&wrapped[1..=NONCE_BYTES]);
    let wrapping = master.wrapping_key(layer).map_err(|_| SealError::Cipher)?;
    let mut sealed = Zeroizing::new(wrapped[1 + NONCE_BYTES..].to_vec());
    let opened = cipher(&wrapping)?
        .open_in_place(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(wrap_aad(layer, kind, file_id)),
            &mut sealed,
        )
        .map_err(|_| SealError::Header)?;
    let mut key = Zeroizing::new([0u8; KEY_BYTES]);
    if opened.len() != KEY_BYTES {
        return Err(SealError::Header);
    }
    key.copy_from_slice(opened);
    Ok(key)
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
    /// file starts with. `fill` supplies the file id, the data key and the
    /// wrap nonce.
    ///
    /// # Errors
    ///
    /// `fill` or the cipher failed.
    pub fn new(
        master: &MasterKey,
        kind: Kind,
        fill: Fill<'_>,
    ) -> Result<(Self, [u8; HEADER_BYTES]), String> {
        let mut file_id = [0u8; FILE_ID_BYTES];
        fill(&mut file_id)?;
        let mut data_key = Zeroizing::new([0u8; KEY_BYTES]);
        fill(&mut *data_key)?;
        let mut nonce = [0u8; NONCE_BYTES];
        fill(&mut nonce)?;
        let wrapped = wrap(master, Layer::Sealed, kind, &file_id, &data_key, nonce)
            .map_err(|e| e.to_string())?;
        let mut header = [0u8; HEADER_BYTES];
        header[..4].copy_from_slice(&MAGIC);
        header[4] = FORMAT;
        header[5] = kind.byte();
        header[6..14].copy_from_slice(&master.id().0);
        header[14..14 + FILE_ID_BYTES].copy_from_slice(&file_id);
        header[14 + FILE_ID_BYTES..].copy_from_slice(&wrapped);
        let sealer = Self {
            key: cipher(&data_key).map_err(|e| e.to_string())?,
            file_id,
            next: 0,
            records: 0,
        };
        Ok((sealer, header))
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
                Aad::from(record_aad(&self.file_id)),
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
    if let Some(&format) = bytes.get(4)
        && format != FORMAT
    {
        return Err(SealError::UnknownFormat(format));
    }
    if bytes.len() < HEADER_BYTES {
        return Err(SealError::Truncated);
    }
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
    wrapped.copy_from_slice(&bytes[14 + FILE_ID_BYTES..HEADER_BYTES]);
    let data_key = unwrap(master, Layer::Sealed, kind, &file_id, &wrapped)?;
    let key = cipher(&data_key)?;

    let mut log = OpenedLog {
        records: Vec::new(),
        key_id,
        torn_tail: false,
    };
    let mut rest = &bytes[HEADER_BYTES..];
    let mut position = 0u64;
    let mut base_ended = false;
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
                Aad::from(record_aad(&file_id)),
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
            _ => return Err(failed),
        }
        position = position.checked_add(1).ok_or(failed)?;
        rest = &after[len..];
    }
    if !base_ended {
        return Err(SealError::Truncated);
    }
    Ok(log)
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
/// key from `fill`, and return the key's id.
///
/// # Errors
///
/// `path` exists, cannot be created or written, or `fill` failed. An
/// existing file is never overwritten: it may be the only copy of a key.
pub fn write_new_key_file(path: &Path, fill: Fill<'_>) -> Result<KeyId, String> {
    use std::io::Write as _;
    let shown = path.display();
    // The key is drawn first: a random source that fails leaves no file.
    let mut bytes = [0u8; KEY_BYTES];
    fill(&mut bytes).map_err(|e| format!("--out '{shown}': {e}"))?;
    let key = MasterKey::from_bytes(bytes);
    zeroize::Zeroize::zeroize(&mut bytes);
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

#[cfg(test)]
mod tests {
    use super::*;

    /// What a test returns.
    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// A key whose every byte is `b`.
    fn key(b: u8) -> MasterKey {
        MasterKey::from_bytes([b; KEY_BYTES])
    }

    /// A fill that writes a counter, so every call gives different bytes
    /// and a test is repeatable.
    fn counting() -> impl Fn(&mut [u8]) -> Result<(), String> {
        let next = std::cell::Cell::new(1u8);
        move |out: &mut [u8]| {
            for byte in out.iter_mut() {
                *byte = next.get();
                next.set(next.get().wrapping_add(1));
            }
            Ok(())
        }
    }

    /// Twelve bytes from [`counting`], for a wrap that needs a nonce.
    fn drawn() -> [u8; NONCE_BYTES] {
        let mut out = [0u8; NONCE_BYTES];
        let _ = counting()(&mut out);
        out
    }

    /// A sealed registry file under `master` holding `records`, then
    /// `appended` after the end of the base.
    fn sealed(
        master: &MasterKey,
        records: &[&[u8]],
        appended: &[&[u8]],
    ) -> Result<Vec<u8>, String> {
        let fill = counting();
        let (mut sealer, header) = LogSealer::new(master, Kind::Registry, &fill)?;
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
        let w = wrap(&m, Layer::Sealed, Kind::Registry, &id, &dek, drawn())
            .map_err(|e| e.to_string())?;
        assert_eq!(w[0], FORMAT, "the envelope starts with its format byte");
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
        let fill = counting();
        let (mut a, ha) = LogSealer::new(&key(1), Kind::Registry, &fill)?;
        let (mut b, hb) = LogSealer::new(&key(1), Kind::Registry, &fill)?;
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
        let failing = |_: &mut [u8]| Err("no entropy".to_string());
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
        bytes[HEADER_BYTES - 20] ^= 1;
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
        let fill = counting();
        let (mut sealer, header) = LogSealer::new(&key(1), Kind::Intake, &fill)?;
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
        let fill = counting();
        let (mut sealer, header) = LogSealer::new(&key(1), Kind::Intake, &fill)?;
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
        let fill = counting();
        let (mut a, _) = LogSealer::new(&key(1), Kind::Registry, &fill)?;
        let (_, header_b) = LogSealer::new(&key(1), Kind::Registry, &fill)?;
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
        let fill = |out: &mut [u8]| {
            if out.len() == KEY_BYTES {
                out.fill(0x42);
            } else {
                out.fill(next.get());
                next.set(next.get() + 1);
            }
            Ok(())
        };
        let (mut a, header_a) = LogSealer::new(&key(1), Kind::Registry, &fill)?;
        let (mut b, header_b) = LogSealer::new(&key(1), Kind::Registry, &fill)?;
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
        let w = wrap(&m, Layer::Sealed, Kind::Registry, &id, &dek, drawn())
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
        let mut w = wrap(&m, Layer::Sealed, Kind::Registry, &id, &dek, drawn())
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
        let fill = counting();
        let (mut sealer, _) = LogSealer::new(&key(1), Kind::Registry, &fill)?;
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
        let fill = counting();
        let (mut sealer, _) = LogSealer::new(&key(1), Kind::Registry, &fill)?;
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
        let fill = counting();
        let (mut sealer, header) = LogSealer::new(&key(1), Kind::Registry, &fill)?;
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
        let fill = counting();
        let (mut sealer, header) = LogSealer::new(&key(1), Kind::Registry, &fill)?;
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
        let fill = counting();
        let (mut sealer, header) = LogSealer::new(&key(1), Kind::Registry, &fill)?;
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
        let fill = counting();
        let (mut sealer, header) = LogSealer::new(&key(1), Kind::Registry, &fill)?;
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

    #[test]
    fn the_system_source_fills_and_two_draws_differ() -> TestResult {
        let (mut a, mut b) = ([0u8; 32], [0u8; 32]);
        system_fill(&mut a)?;
        system_fill(&mut b)?;
        assert_ne!(a, b, "two draws of 32 bytes are not equal");
        Ok(())
    }
}
