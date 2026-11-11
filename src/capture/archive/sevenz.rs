// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! 7-Zip archives, unencrypted or AES-256.
//!
//! A 7z is read the way a ZIP is: from a seekable file, the archive named on
//! the command line where it lies and a nested one copied out first (see
//! [`super::zipped`]). Its members are walked through the same layers.
//!
//! # One password per archive
//!
//! 7-Zip encrypts whole blocks, and in a solid archive one block holds many
//! members, so a password is tried on the ARCHIVE, not member by member. The
//! [`Keyring`](super::password::Keyring) is asked once per archive: the
//! remembered password, the configured ones, then the prompt. Each try reads
//! the archive in trial: a stream that breaks or a CRC that fails means the
//! password was wrong, and the trial rolls back. A header-encrypted archive
//! is tried the same way, since not even its member list opens without the
//! password.
//!
//! # Passwords are UTF-16
//!
//! The format defines a password as the UTF-16LE encoding of its text, so a
//! typed password's NFC and NFD forms are what vary; there are no code-page
//! spellings as ZIP has.
//!
//! # Key derivation is bounded
//!
//! A 7z key costs `2^NumCyclesPower` SHA-256 rounds, and the archive chooses
//! the power. `sevenz-rust2` refuses a power above 24, 7-Zip's own ceiling
//! (its default is 19), so a crafted archive cannot make one attempt take
//! hours. A refusal is `bound_exceeded (7z key derivation)` (Invariant "Every attacker-keyed map has a bound and a stated eviction policy").
//!
//! # A walk that stops reads no further
//!
//! A walk stops at the inflation ceiling, at the entry cap, at a member that
//! cannot be written, and when a pointer has found its member. The read of
//! the archive ends there: no later block is decoded, no later member is
//! counted, extracted or reported, and no nested archive in a later block is
//! opened or asked a password for. `sevenz-rust2` has two calls that look
//! alike here. `for_each_entries` reads `false` as "skip the rest of this
//! block" and goes on with the next block; an archive written one member at a
//! time has one block per member, so that call never stopped. The reader uses
//! `for_each_entries_with_decision` and [`EntryDecision::Stop`].

use std::io::{self, Read, Seek};

use sevenz_rust2::EntryDecision;

use super::password::{Container, Trial, Unlock};
use super::{Encryption, Flow, Inflating, Layer, SkipReason, Stop, Walker, member_name};

/// The 7z method id of AES-256 with SHA-256 key derivation.
const AES256_SHA256: &[u8] = &[0x06, 0xF1, 0x07, 0x01];

/// A member's data, held to the size its header declares.
///
/// sevenz-rust2 checks a member's CRC only once the declared size has been
/// read, so a decoder that stops early ends the stream with `Ok(0)` and no
/// check at all. A wrong password makes that happen: the key decrypts to
/// noise, and noise whose first byte is 0x00 is LZMA2's end marker. Read as
/// is, the member is "empty" and the password looks right. Held to its size,
/// the early end is an error, which a trial counts against the password and
/// an ordinary read reports as a broken member.
struct Declared<R> {
    /// The member's data as the library decodes it.
    inner: R,
    /// Bytes read so far.
    got: u64,
    /// The size the member's header declares.
    size: u64,
}

impl<R: Read> Declared<R> {
    /// `inner`, held to `size` bytes.
    fn new(inner: R, size: u64) -> Self {
        Self {
            inner,
            got: 0,
            size,
        }
    }
}

impl<R: Read> Read for Declared<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        if n == 0 && !buf.is_empty() && self.got < self.size {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!(
                    "the 7z member ended after {} of {} bytes",
                    self.got, self.size
                ),
            ));
        }
        self.got += n as u64;
        Ok(n)
    }
}

/// Whether a `sevenz-rust2` error is its refusal of an over-large
/// NumCyclesPower. Matched on the crate's message, which a test pins, so an
/// upgrade that rewords it fails the build rather than the bound.
fn is_cycles_refusal(e: &sevenz_rust2::Error) -> bool {
    e.to_string().contains("num_cycles_power")
}

/// How opening a 7z's member list went.
enum Listing {
    /// Readable without a password.
    Open {
        /// Whether any block is encrypted.
        encrypted: bool,
        /// Entries the archive lists.
        entries: usize,
    },
    /// The member list itself is encrypted.
    HeaderLocked,
    /// A key derivation past the bound was refused.
    OverBound,
    /// Not a readable 7z.
    Broken(String),
}

/// What the 7z in `file` is, without a password.
fn listing(file: &mut std::fs::File) -> Listing {
    let _ = file.seek(io::SeekFrom::Start(0));
    match sevenz_rust2::Archive::read(file, &sevenz_rust2::Password::empty()) {
        Ok(archive) => Listing::Open {
            encrypted: archive.blocks.iter().any(|b| {
                b.coders
                    .iter()
                    .any(|c| c.encoder_method_id() == AES256_SHA256)
            }),
            entries: archive.files.len(),
        },
        Err(sevenz_rust2::Error::PasswordRequired) => Listing::HeaderLocked,
        Err(e) if is_cycles_refusal(&e) => Listing::OverBound,
        Err(e) => Listing::Broken(e.to_string()),
    }
}

impl Walker<'_> {
    /// Walk the members of one 7z archive.
    pub(super) fn walk_7z(
        &mut self,
        src: &mut dyn Read,
        label: &str,
        layers: &[Layer],
        depth: usize,
    ) -> Flow {
        let mut source = match self.seekable_source(src, label, "7z") {
            Ok(s) => s,
            Err(flow) => return flow,
        };
        let mut next = layers.to_vec();
        next.push(Layer::SevenZip);
        match listing(&mut source.file) {
            Listing::Broken(detail) => {
                self.out.stops.push(Stop::Broken {
                    container: label.to_string(),
                    detail,
                });
                Flow::Continue
            }
            Listing::OverBound => {
                self.skip_enc(
                    label,
                    SkipReason::BoundExceeded("7z key derivation".to_string()),
                    Encryption::SevenZipAes256,
                );
                Flow::Continue
            }
            Listing::Open { entries, .. } if entries > self.limits.max_entries => {
                self.out.stops.push(Stop::EntryCap {
                    limit: self.limits.max_entries,
                });
                Flow::Abort
            }
            Listing::Open {
                encrypted: false, ..
            } => {
                let empty = sevenz_rust2::Password::empty();
                match self.read_7z(&mut source.file, &empty, label, &next, depth) {
                    Ok(flow) => flow,
                    Err(e) => {
                        self.out.stops.push(Stop::Broken {
                            container: label.to_string(),
                            detail: e.to_string(),
                        });
                        Flow::Continue
                    }
                }
            }
            Listing::Open {
                encrypted: true, ..
            }
            | Listing::HeaderLocked => self.read_7z_locked(&mut source.file, label, &next, depth),
        }
    }

    /// Offer an encrypted 7z to the keyring, reading it in trial with each
    /// spelling of each password.
    fn read_7z_locked(
        &mut self,
        file: &mut std::fs::File,
        label: &str,
        layers: &[Layer],
        depth: usize,
    ) -> Flow {
        let Some(keyring) = self.keyring.take() else {
            self.skip_enc(
                label,
                SkipReason::EncryptedNoPassword,
                Encryption::SevenZipAes256,
            );
            return Flow::Continue;
        };
        let outer = self.encryption;
        self.encryption = Encryption::SevenZipAes256;
        let mut over_bound = false;
        let mut try_one = |spelling: &[u8]| -> Trial<Flow> {
            // Built at the moment of the call and dropped straight after:
            // the crate's `Password` derives `Debug` and `Clone` and is never
            // cleared, so it must not outlive this attempt.
            let password = sevenz_rust2::Password::from_raw(spelling);
            let mark = self.checkpoint();
            let outer_trial = self.trial;
            self.trial = true;
            self.rejected = false;
            let result = self.read_7z(file, &password, label, layers, depth);
            drop(password);
            self.trial = outer_trial;
            match result {
                Err(e) if is_cycles_refusal(&e) => {
                    over_bound = true;
                    self.rollback(mark);
                    Trial::Unsupported("7z key derivation".to_string())
                }
                // A wrong password shows as a bad-password error, a failed
                // CRC, or a stream that will not decode: 7z has no check
                // value, so every failure on trial is the password's.
                Err(_) => {
                    self.rejected = false;
                    self.rollback(mark);
                    Trial::Wrong
                }
                Ok(_) if self.rejected || self.trial_broke(&mark) => {
                    self.rejected = false;
                    self.rollback(mark);
                    Trial::Wrong
                }
                Ok(flow) => Trial::Opened(flow),
            }
        };
        let outcome = keyring.unlock(label, "(the archive)", Container::SevenZip, &mut try_one);
        self.keyring = Some(keyring);
        self.encryption = outer;
        match outcome {
            Unlock::Opened(flow) => flow,
            Unlock::NoPassword => {
                self.skip_enc(
                    label,
                    SkipReason::EncryptedNoPassword,
                    Encryption::SevenZipAes256,
                );
                Flow::Continue
            }
            Unlock::WrongPassword => {
                self.skip_enc(
                    label,
                    SkipReason::EncryptedWrongPassword,
                    Encryption::SevenZipAes256,
                );
                Flow::Continue
            }
            Unlock::Unsupported(what) if over_bound => {
                self.skip_enc(
                    label,
                    SkipReason::BoundExceeded(what),
                    Encryption::SevenZipAes256,
                );
                Flow::Continue
            }
            Unlock::Unsupported(why) => {
                self.skip_enc(
                    label,
                    SkipReason::EncryptionUnsupported(why),
                    Encryption::SevenZipAes256,
                );
                Flow::Continue
            }
        }
    }

    /// Read every member of the 7z in `file` with `password`, walking each.
    fn read_7z(
        &mut self,
        file: &mut std::fs::File,
        password: &sevenz_rust2::Password,
        label: &str,
        layers: &[Layer],
        depth: usize,
    ) -> Result<Flow, sevenz_rust2::Error> {
        file.seek(io::SeekFrom::Start(0))
            .map_err(sevenz_rust2::Error::from)?;
        let mut reader = sevenz_rust2::ArchiveReader::new(&mut *file, password.clone())?;
        // `sevenz-rust2` computes the map from blocks to packed streams only
        // after it reads the header's file information. A header that declares
        // blocks and no file information leaves the map empty, and decoding
        // then indexes it for block 0 and panics, which a release build turns
        // into an abort. One entry per block is the map the crate computes and
        // bounds-checks when it gets that far.
        let archive = reader.archive();
        if archive.stream_map.block_first_pack_stream_index().len() != archive.blocks.len() {
            return Err(sevenz_rust2::Error::Other(
                "the 7z header declares blocks but not the streams that hold them".into(),
            ));
        }
        let mut flow = Flow::Continue;
        // `for_each_entries_with_decision`, not `for_each_entries`: that one
        // takes `false` to mean "skip the rest of this BLOCK" and goes on to
        // the next block, and an archive made one member at a time has one
        // block per member. A walk that had stopped then met every later
        // member (SEVENZ-READ-STOP). `Stop` ends the read of the archive.
        reader.for_each_entries_with_decision(|entry, data| {
            self.entries += 1;
            if self.entries > self.limits.max_entries {
                // The cap counts every container of one input together, so a
                // 7z inside another container can pass it part-way through.
                self.out.stops.push(Stop::EntryCap {
                    limit: self.limits.max_entries,
                });
                flow = Flow::Abort;
                return Ok(EntryDecision::Stop);
            }
            if entry.is_directory() {
                if self.wanted.is_none() {
                    self.out.directories += 1;
                }
                return Ok(EntryDecision::Continue);
            }
            let child = format!("{label}/{}", member_name(entry.name().as_bytes()));
            if !self.leads_to_wanted(&child) {
                // Solid blocks must be read through in order: drain, never skip.
                io::copy(data, &mut io::sink()).map_err(sevenz_rust2::Error::from)?;
                return Ok(EntryDecision::Continue);
            }
            if !self.claim(&child) {
                self.skip(&child, SkipReason::DuplicateName);
                io::copy(data, &mut io::sink()).map_err(sevenz_rust2::Error::from)?;
                return Ok(EntryDecision::Continue);
            }
            if let Some(keep) = self.keep {
                let file_name = child.rsplit('/').next().unwrap_or(&child);
                if !keep(file_name) {
                    self.out.filtered += 1;
                    io::copy(data, &mut io::sink()).map_err(sevenz_rust2::Error::from)?;
                    return Ok(EntryDecision::Continue);
                }
            }
            let mut inner = Inflating {
                inner: Declared::new(data, entry.size()),
                used: std::rc::Rc::clone(&self.used),
                limit: self.limits.max_inflated_bytes,
            };
            let step = self.walk(&mut inner, &child, layers, depth);
            // What the walk left unread still has to pass through the
            // decoder for the block's CRC to be checked.
            let _ = io::copy(&mut inner, &mut io::sink());
            if step == Flow::Abort || (self.wanted.is_some() && !self.out.members.is_empty()) {
                flow = Flow::Abort;
                return Ok(EntryDecision::Stop);
            }
            Ok(EntryDecision::Continue)
        })?;
        Ok(flow)
    }
}

#[cfg(test)]
pub(crate) mod testutil {
    //! Build 7z fixtures in a test, with the dev-only encoder. The password is
    //! always the caller's, minted at runtime.

    /// The error a fallible fixture builder here returns.
    pub type TestError = Box<dyn std::error::Error>;

    /// A 7z of `entries`, LZMA2, AES-256 with `password` when given; the
    /// member list encrypted too when `encrypt_header`. Each file is its own
    /// block. A name that ends in `/` is a directory entry, and its data is
    /// not used.
    pub fn build(
        entries: &[(&str, &[u8])],
        password: Option<&str>,
        encrypt_header: bool,
    ) -> Result<Vec<u8>, TestError> {
        build_with(
            entries,
            password,
            encrypt_header,
            sevenz_rust2::EncoderMethod::LZMA2,
        )
    }

    /// A 7z of `entries` stored without compression (the COPY method),
    /// AES-256 with `password` when given, the member list not encrypted.
    /// A wrong key then decrypts every member to noise of the member's full
    /// size, which only the CRC at its end gives away.
    pub fn build_stored(
        entries: &[(&str, &[u8])],
        password: Option<&str>,
    ) -> Result<Vec<u8>, TestError> {
        build_with(entries, password, false, sevenz_rust2::EncoderMethod::COPY)
    }

    /// A 7z of `entries` packed with `method`, each file its own block.
    fn build_with(
        entries: &[(&str, &[u8])],
        password: Option<&str>,
        encrypt_header: bool,
        method: sevenz_rust2::EncoderMethod,
    ) -> Result<Vec<u8>, TestError> {
        use sevenz_rust2::encoder_options::AesEncoderOptions;
        use sevenz_rust2::{ArchiveEntry, ArchiveWriter, Password};
        let mut w = ArchiveWriter::new(std::io::Cursor::new(Vec::new()))
            .map_err(|e| format!("writer: {e:?}"))?;
        match password {
            Some(pw) => {
                w.set_content_methods(vec![
                    AesEncoderOptions::new(Password::from(pw)).into(),
                    method.into(),
                ]);
                w.set_encrypt_header(encrypt_header);
            }
            None => {
                w.set_content_methods(vec![method.into()]);
            }
        }
        for (name, data) in entries {
            match name.strip_suffix('/') {
                Some(dir) => w.push_archive_entry::<&[u8]>(ArchiveEntry::new_directory(dir), None),
                None => w.push_archive_entry(ArchiveEntry::new_file(name), Some(*data)),
            }
            .map_err(|e| format!("entry: {e:?}"))?;
        }
        Ok(w.finish()
            .map_err(|e| format!("finish: {e:?}"))?
            .into_inner())
    }

    /// `archive` with the NumCyclesPower of its header's AES coder raised to
    /// `power`, and the start header's checksums redone to match: an archive
    /// that asks for `2^power` key-derivation rounds.
    pub fn with_cycles_power(mut archive: Vec<u8>, power: u8) -> Result<Vec<u8>, TestError> {
        let id = [0x06u8, 0xF1, 0x07, 0x01];
        let at = archive
            .windows(4)
            .rposition(|w| w == id)
            .ok_or("an AES coder in the plain header")?;
        // The id, the properties' size, then the first property byte, whose
        // low six bits are NumCyclesPower.
        let props = at + 4 + 1;
        archive[props] = (archive[props] & 0xC0) | (power & 0x3F);
        refresh_checksums(archive)
    }

    /// `archive` with the first byte of its content AES coder's IV set to
    /// `value`, checksums redone. AES-CBC makes the first decrypted byte the
    /// block's decryption XOR `IV[0]`, so stepping `value` through all 256
    /// values walks that byte through all 256 values too, for any key.
    pub fn with_iv_first_byte(mut archive: Vec<u8>, value: u8) -> Result<Vec<u8>, TestError> {
        let id = [0x06u8, 0xF1, 0x07, 0x01];
        let at = archive
            .windows(4)
            .rposition(|w| w == id)
            .ok_or("an AES coder in the plain header")?;
        // 7-Zip's AES properties: flags and NumCyclesPower, then the sizes
        // byte, then the salt, then the IV. Bit 7 and the high nibble give the
        // salt's size, bit 6 and the low nibble the IV's.
        let props = at + 4 + 1;
        let (b0, b1) = (archive[props], archive[props + 1]);
        let salt = usize::from(b0 >> 7) + usize::from(b1 >> 4);
        let iv = usize::from((b0 >> 6) & 1) + usize::from(b1 & 0x0F);
        assert!(iv > 0, "the AES coder carries no IV");
        archive[props + 2 + salt] = value;
        refresh_checksums(archive)
    }

    /// A solid 7z of `entries`: one block holding every member, LZMA2.
    pub fn build_solid(entries: &[(&str, &[u8])]) -> Result<Vec<u8>, TestError> {
        use sevenz_rust2::{ArchiveEntry, ArchiveWriter, EncoderMethod, SourceReader};
        let mut w = ArchiveWriter::new(std::io::Cursor::new(Vec::new()))
            .map_err(|e| format!("writer: {e:?}"))?;
        w.set_content_methods(vec![EncoderMethod::LZMA2.into()]);
        let (names, readers) = entries
            .iter()
            .map(|(name, data)| (ArchiveEntry::new_file(name), SourceReader::new(*data)))
            .unzip();
        w.push_archive_entries(names, readers)
            .map_err(|e| format!("entries: {e:?}"))?;
        Ok(w.finish()
            .map_err(|e| format!("finish: {e:?}"))?
            .into_inner())
    }

    /// `archive` with block `block` damaged: the last 8 bytes of the block's
    /// first packed stream are inverted, which the member's CRC (or the
    /// decoder before it) catches when that block is read and nothing else
    /// notices. `password` reads the member list when it is encrypted. No
    /// checksum is redone: a packed stream is covered by its member's CRC
    /// only.
    pub fn with_damaged_block(
        mut archive: Vec<u8>,
        password: Option<&str>,
        block: usize,
    ) -> Result<Vec<u8>, TestError> {
        use sevenz_rust2::{Archive, Password};
        let password = password.map_or_else(Password::empty, Password::from);
        let listed = Archive::read(&mut std::io::Cursor::new(&archive), &password)
            .map_err(|e| format!("list: {e:?}"))?;
        let stream = *listed
            .stream_map
            .block_first_pack_stream_index()
            .get(block)
            .ok_or_else(|| format!("no block {block}"))?;
        let offset = listed.stream_map.pack_stream_offsets()[stream];
        let size = listed.pack_sizes()[stream];
        let end = usize::try_from(32 + listed.pack_pos() + offset + size)
            .map_err(|e| format!("offset: {e:?}"))?;
        if size < 8 || end > archive.len() {
            return Err(format!("block {block} has no 8 bytes to damage").into());
        }
        for b in &mut archive[end - 8..end] {
            *b = !*b;
        }
        Ok(archive)
    }

    /// Redo the next-header CRC and the start header's CRC after a patch.
    fn refresh_checksums(mut archive: Vec<u8>) -> Result<Vec<u8>, TestError> {
        let next_offset = u64::from_le_bytes(
            archive[12..20]
                .try_into()
                .map_err(|e| format!("8: {e:?}"))?,
        ) as usize;
        let next_size = u64::from_le_bytes(
            archive[20..28]
                .try_into()
                .map_err(|e| format!("8: {e:?}"))?,
        ) as usize;
        let header = 32 + next_offset;
        let crc = crc32(&archive[header..header + next_size]);
        archive[28..32].copy_from_slice(&crc.to_le_bytes());
        let start = crc32(&archive[12..32]);
        archive[8..12].copy_from_slice(&start.to_le_bytes());
        Ok(archive)
    }

    /// CRC-32 (IEEE), bit by bit: a fixture helper, not a hot path.
    fn crc32(data: &[u8]) -> u32 {
        let mut crc = 0xFFFF_FFFFu32;
        for b in data {
            crc ^= u32::from(*b);
            for _ in 0..8 {
                let mask = (crc & 1).wrapping_neg();
                crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
            }
        }
        !crc
    }
}

#[cfg(test)]
mod tests {
    use super::super::password::{
        ArchivePassword, Candidate, Keyring, PromptAnswer, PromptRequest, Prompter, Source,
    };
    use super::super::tar::testutil::{Spec, build as build_tar};
    use super::super::*;
    use super::Declared;
    use super::testutil::{
        build, build_solid, build_stored, with_cycles_power, with_damaged_block, with_iv_first_byte,
    };
    use std::io::{Read, Write};

    type TestError = Box<dyn std::error::Error>;

    fn pcap_bytes(payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&0xa1b2_c3d4u32.to_le_bytes());
        out.extend_from_slice(&2u16.to_le_bytes());
        out.extend_from_slice(&4u16.to_le_bytes());
        out.extend_from_slice(&[0; 8]);
        out.extend_from_slice(&65535u32.to_le_bytes());
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(&1_700_000_000u32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        out.extend_from_slice(payload);
        out
    }

    fn limits() -> Limits {
        Limits {
            max_inflated_bytes: 64 * 1024 * 1024,
            max_entries: MAX_ENTRIES,
            max_depth: MAX_DEPTH,
        }
    }

    fn secret(label: &str) -> &'static str {
        crate::test_material::key_str(label)
    }

    fn ring_of(passwords: &[&str]) -> Result<Keyring, TestError> {
        let candidates = passwords
            .iter()
            .map(|p| -> Result<Candidate, TestError> {
                Ok(Candidate {
                    password: ArchivePassword::from_bytes(p.as_bytes())
                        .map_err(|e| format!("valid: {e:?}"))?,
                    source: Source::File,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Keyring::new(candidates, None))
    }

    #[test]
    fn a_member_that_ends_before_its_declared_size_is_an_error() -> Result<(), TestError> {
        let mut r = Declared::new(&b"abc"[..], 5);
        let mut out = Vec::new();
        let e = r.read_to_end(&mut out).err().ok_or("short")?;
        assert_eq!(e.kind(), io::ErrorKind::UnexpectedEof);
        assert_eq!(out, b"abc");
        assert!(e.to_string().contains("3 of 5"), "{e}");
        Ok(())
    }

    #[test]
    fn a_member_of_exactly_its_declared_size_reads_clean() -> Result<(), TestError> {
        let mut r = Declared::new(&b"abcde"[..], 5);
        let mut out = Vec::new();
        assert_eq!(
            r.read_to_end(&mut out)
                .map_err(|e| format!("exact: {e:?}"))?,
            5
        );
        assert_eq!(
            r.read(&mut [0u8; 4])
                .map_err(|e| format!("past the end: {e:?}"))?,
            0
        );
        Ok(())
    }

    #[test]
    fn an_empty_buffer_is_not_mistaken_for_the_end() -> Result<(), TestError> {
        let mut r = Declared::new(&b"abc"[..], 3);
        assert_eq!(
            r.read(&mut [])
                .map_err(|e| format!("zero-length read: {e:?}"))?,
            0
        );
        let mut out = Vec::new();
        assert_eq!(
            r.read_to_end(&mut out)
                .map_err(|e| format!("then the rest: {e:?}"))?,
            3
        );
        Ok(())
    }

    fn write(
        dir: &std::path::Path,
        name: &str,
        bytes: &[u8],
    ) -> Result<std::path::PathBuf, TestError> {
        let p = dir.join(name);
        std::fs::write(&p, bytes).map_err(|e| format!("write: {e:?}"))?;
        Ok(p)
    }

    fn expand_with(
        path: &std::path::Path,
        keyring: Option<&mut Keyring>,
    ) -> Result<Expansion, TestError> {
        Ok(expand_filtered_with(path, &limits(), None, keyring)
            .map_err(|e| format!("expand: {e:?}"))?)
    }

    /// A 7z header that declares blocks and no file information leaves the
    /// decoder's stream map empty, and `sevenz-rust2` indexed it for block 0
    /// and panicked: in a release build, which aborts on a panic, one hostile
    /// archive ended the run. Found by `archive_fuzz_replay_test`; the input
    /// is a bit-flipped AES-256 7z it built. It is refused, not opened.
    #[test]
    fn a_7z_whose_blocks_have_no_stream_map_is_refused() -> Result<(), TestError> {
        let archive = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/archive/7z-blocks-without-stream-map.7z"
        ))
        .map_err(|e| format!("fixture: {e:?}"))?;
        let tmp = tempfile::tempdir().map_err(|e| format!("tmp: {e:?}"))?;
        let path = write(tmp.path(), "hostile.7z", &archive)?;
        let exp = expand_with(&path, Some(&mut ring_of(&["fz5d1763f9c4a"])?))?;
        assert!(exp.members.is_empty(), "{:?}", exp.members);
        assert!(
            !exp.skipped.is_empty() || !exp.stops.is_empty(),
            "the refusal is reported"
        );
        Ok(())
    }

    #[test]
    fn an_unencrypted_7z_reads_like_a_tar() -> Result<(), TestError> {
        let tmp = tempfile::tempdir().map_err(|e| format!("tmp: {e:?}"))?;
        let a = pcap_bytes(b"alpha");
        let path = write(
            tmp.path(),
            "set.7z",
            &build(&[("set/a.pcap", &a), ("notes.txt", b"lab")], None, false)?,
        )?;
        let exp = expand_with(&path, None)?;
        assert_eq!(exp.members.len(), 1, "{:?} {:?}", exp.skipped, exp.stops);
        assert_eq!(
            exp.members[0].label,
            format!("{}/set/a.pcap", path.display())
        );
        assert_eq!(exp.members[0].layers, vec![Layer::SevenZip]);
        assert_eq!(exp.members[0].encryption, Encryption::None);
        assert_eq!(
            std::fs::read(&exp.members[0].path).map_err(|e| format!("read: {e:?}"))?,
            a
        );
        Ok(())
    }

    #[test]
    fn an_aes_7z_opens_with_the_right_password_and_says_why_not_otherwise() -> Result<(), TestError>
    {
        let tmp = tempfile::tempdir().map_err(|e| format!("tmp: {e:?}"))?;
        let a = pcap_bytes(b"secret");
        for encrypt_header in [false, true] {
            let path = write(
                tmp.path(),
                "aes.7z",
                &build(&[("a.pcap", &a)], Some(secret("7z-right")), encrypt_header)?,
            )?;
            let exp = expand_with(&path, Some(&mut ring_of(&["x", secret("7z-right")])?))?;
            assert_eq!(
                exp.members.len(),
                1,
                "header {encrypt_header}: {:?}",
                exp.skipped
            );
            assert_eq!(exp.members[0].encryption, Encryption::SevenZipAes256);
            assert_eq!(
                std::fs::read(&exp.members[0].path).map_err(|e| format!("read: {e:?}"))?,
                a
            );

            let exp = expand_with(&path, Some(&mut ring_of(&[secret("7z-wrong")])?))?;
            assert!(exp.members.is_empty());
            assert!(
                matches!(exp.skipped.as_slice(), [s] if s.reason == SkipReason::EncryptedWrongPassword),
                "{:?} {:?}",
                exp.skipped,
                exp.stops
            );

            let exp = expand_with(&path, None)?;
            assert!(
                matches!(exp.skipped.as_slice(), [s] if s.reason == SkipReason::EncryptedNoPassword),
                "{:?}",
                exp.skipped
            );
        }
        Ok(())
    }

    /// A wrong key decrypts to noise, and LZMA2 reads some noise without
    /// complaint: a first byte of 0x00 is its end-of-stream marker, so the
    /// member ends empty, and 0x01/0x02 open an uncompressed chunk that
    /// passes the noise through for the CRC to catch at the end. Neither may
    /// count as the password opening the archive. Every first byte is tried,
    /// so both cases are hit on every run rather than one run in ~100.
    #[test]
    fn no_first_decrypted_byte_lets_a_wrong_password_open_a_7z() -> Result<(), TestError> {
        let tmp = tempfile::tempdir().map_err(|e| format!("tmp: {e:?}"))?;
        let a = pcap_bytes(b"every-first-byte");
        // Two key-derivation rounds instead of 2^19: the key no longer
        // matches what the content was encrypted with, which is the point.
        let base = with_cycles_power(build(&[("a.pcap", &a)], Some(secret("7z-iv")), false)?, 1)?;
        let mut opened = Vec::new();
        for value in 0..=u8::MAX {
            let path = write(
                tmp.path(),
                &format!("iv{value}.7z"),
                &with_iv_first_byte(base.clone(), value)?,
            )?;
            let exp = expand_with(&path, Some(&mut ring_of(&[secret("7z-iv-wrong")])?))?;
            if !exp.members.is_empty()
                || !matches!(exp.skipped.as_slice(), [s] if s.reason == SkipReason::EncryptedWrongPassword)
            {
                opened.push((value, exp.skipped, exp.stops));
            }
        }
        assert!(
            opened.is_empty(),
            "a wrong password opened {} of 256: {opened:?}",
            opened.len()
        );
        Ok(())
    }

    #[test]
    fn a_decomposed_password_opens_a_7z_made_with_the_composed_one() -> Result<(), TestError> {
        let tmp = tempfile::tempdir().map_err(|e| format!("tmp: {e:?}"))?;
        let base = secret("7z-nfc");
        let composed = format!("{}\u{00fc}{}", &base[..6], &base[6..12]);
        let decomposed = format!("{}u\u{0308}{}", &base[..6], &base[6..12]);
        let a = pcap_bytes(b"nfc");
        let path = write(
            tmp.path(),
            "nfc.7z",
            &build(&[("a.pcap", &a)], Some(&composed), false)?,
        )?;
        let mut keys = ring_of(&[&decomposed])?;
        let exp = expand_with(&path, Some(&mut keys))?;
        assert_eq!(exp.members.len(), 1, "{:?}", exp.skipped);
        assert_eq!(keys.attempts(), 1, "every spelling is one attempt");
        Ok(())
    }

    #[test]
    fn a_key_derivation_past_the_bound_is_refused_quickly() -> Result<(), TestError> {
        let tmp = tempfile::tempdir().map_err(|e| format!("tmp: {e:?}"))?;
        let base = build(
            &[("a.pcap", &pcap_bytes(b"slow"))],
            Some(secret("7z-slow")),
            true,
        )?;
        let path = write(tmp.path(), "slow.7z", &with_cycles_power(base, 40)?)?;
        let started = std::time::Instant::now();
        let exp = expand_with(&path, Some(&mut ring_of(&[secret("7z-slow")])?))?;
        assert!(started.elapsed() < std::time::Duration::from_secs(10));
        assert!(exp.members.is_empty());
        assert!(
            matches!(exp.skipped.as_slice(), [s] if s.reason.code() == "bound_exceeded"
                && s.reason.to_string().contains("7z key derivation")),
            "{:?} {:?}",
            exp.skipped,
            exp.stops
        );
        Ok(())
    }

    #[test]
    fn a_password_7z_nested_in_a_tgz_opens() -> Result<(), TestError> {
        let tmp = tempfile::tempdir().map_err(|e| format!("tmp: {e:?}"))?;
        let a = pcap_bytes(b"deep");
        let sz = build(&[("a.pcap", &a)], Some(secret("7z-nest")), false)?;
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(&build_tar(&[Spec::file("inner.7z", &sz)]))
            .map_err(|e| format!("gzip: {e:?}"))?;
        let path = write(
            tmp.path(),
            "outer.tgz",
            &gz.finish().map_err(|e| format!("gzip: {e:?}"))?,
        )?;
        let exp = expand_with(&path, Some(&mut ring_of(&[secret("7z-nest")])?))?;
        assert_eq!(exp.members.len(), 1, "{:?} {:?}", exp.skipped, exp.stops);
        assert_eq!(
            exp.members[0].layers,
            vec![Layer::Gzip, Layer::Tar, Layer::SevenZip]
        );
        Ok(())
    }

    // ── SEVENZ-READ-STOP: a stopped walk reads no later block ───────────
    //
    // `build` writes one block per member, which is the layout the defect
    // needed: the crate's `for_each_entries` treats `false` as "skip the rest
    // of this block", so a walk that had stopped still met every later block.

    /// What one walk of the archive at a path did.
    struct Walked {
        /// Archive entries the walk met, of every kind.
        entries: usize,
        /// What it found.
        out: Expansion,
    }

    /// Walk `path` the way [`expand_filtered_with`] and [`extract_member_with`]
    /// do, and keep the walker's entry count, which neither returns.
    fn walk_file(
        path: &std::path::Path,
        wanted: Option<&str>,
        lim: &Limits,
        keyring: Option<&mut Keyring>,
    ) -> Result<Walked, TestError> {
        let mut file =
            std::io::BufReader::new(std::fs::File::open(path).map_err(|e| format!("open: {e:?}"))?);
        let root = path.display().to_string();
        let mut w = Walker::new(lim, wanted, path, &root);
        w.keyring = keyring;
        let _ = w.walk(&mut file, &root, &[], 0);
        if let Some(e) = w.fatal.take() {
            return Err(format!("walk: {e:?}").into());
        }
        Ok(Walked {
            entries: w.entries,
            out: w.out,
        })
    }

    /// The limits of [`limits`] with `max_entries` and `max_inflated_bytes`
    /// replaced.
    fn limits_of(max_entries: usize, max_inflated_bytes: u64) -> Limits {
        Limits {
            max_inflated_bytes,
            max_entries,
            ..limits()
        }
    }

    /// Three captures, each in its own block.
    fn three() -> [(&'static str, Vec<u8>); 3] {
        [
            ("a.pcap", pcap_bytes(b"alpha-alpha-alpha")),
            ("b.pcap", pcap_bytes(b"bravo-bravo-bravo")),
            ("c.pcap", pcap_bytes(b"charlie-charlie-charlie")),
        ]
    }

    /// `members` as [`build`] takes them.
    fn refs<'a>(members: &'a [(&'a str, Vec<u8>)]) -> Vec<(&'a str, &'a [u8])> {
        members.iter().map(|(n, d)| (*n, d.as_slice())).collect()
    }

    /// The label of member `name` of the archive at `path`.
    fn label_of(path: &std::path::Path, name: &str) -> String {
        format!("{}/{name}", path.display())
    }

    /// The labels of the members a walk wrote, less the archive's path.
    fn names(path: &std::path::Path, out: &Expansion) -> Vec<String> {
        let prefix = format!("{}/", path.display());
        out.members
            .iter()
            .map(|m| m.label.trim_start_matches(&prefix).to_string())
            .collect()
    }

    /// A prompter that records every request and answers none.
    struct Recording(std::sync::Arc<parking_lot::Mutex<Vec<PromptRequest>>>);

    impl Prompter for Recording {
        fn ask(&mut self, request: &PromptRequest) -> PromptAnswer {
            self.0.lock().push(request.clone());
            PromptAnswer::Skip
        }
    }

    /// A tar of `count` small captures named `t0.pcap`, `t1.pcap` and so on.
    fn tar_of(count: usize) -> Vec<u8> {
        let files: Vec<(String, Vec<u8>)> = (0..count)
            .map(|i| {
                (
                    format!("t{i}.pcap"),
                    pcap_bytes(format!("tar-{i}").as_bytes()),
                )
            })
            .collect();
        let specs: Vec<Spec<'_>> = files.iter().map(|(n, d)| Spec::file(n, d)).collect();
        build_tar(&specs)
    }

    #[test]
    fn a_pointer_to_the_first_member_reads_one_block() -> Result<(), TestError> {
        let tmp = tempfile::tempdir().map_err(|e| format!("tmp: {e:?}"))?;
        let members = three();
        let path = write(tmp.path(), "set.7z", &build(&refs(&members), None, false)?)?;
        let walked = walk_file(&path, Some(&label_of(&path, "a.pcap")), &limits(), None)?;
        assert_eq!(
            names(&path, &walked.out),
            ["a.pcap"],
            "the members written, in archive order"
        );
        assert_eq!(walked.entries, 1, "blocks after the found member were read");
        assert!(walked.out.stops.is_empty(), "{:?}", walked.out.stops);
        Ok(())
    }

    #[test]
    fn a_pointer_to_a_middle_member_reads_up_to_it_and_no_further() -> Result<(), TestError> {
        let tmp = tempfile::tempdir().map_err(|e| format!("tmp: {e:?}"))?;
        let members = three();
        let path = write(tmp.path(), "set.7z", &build(&refs(&members), None, false)?)?;
        let walked = walk_file(&path, Some(&label_of(&path, "b.pcap")), &limits(), None)?;
        assert_eq!(
            names(&path, &walked.out),
            ["b.pcap"],
            "the members written, in archive order"
        );
        assert_eq!(walked.entries, 2, "the archive entries this walk met");
        Ok(())
    }

    #[test]
    fn a_pointer_to_the_last_member_reads_every_block() -> Result<(), TestError> {
        let tmp = tempfile::tempdir().map_err(|e| format!("tmp: {e:?}"))?;
        let members = three();
        let path = write(tmp.path(), "set.7z", &build(&refs(&members), None, false)?)?;
        let walked = walk_file(&path, Some(&label_of(&path, "c.pcap")), &limits(), None)?;
        assert_eq!(
            names(&path, &walked.out),
            ["c.pcap"],
            "the members written, in archive order"
        );
        assert_eq!(walked.entries, 3, "the archive entries this walk met");
        assert_eq!(
            std::fs::read(&walked.out.members[0].path).map_err(|e| format!("read: {e:?}"))?,
            members[2].1,
            "the extracted file holds the member's bytes"
        );
        Ok(())
    }

    #[test]
    fn a_pointer_to_no_member_reads_every_block_and_finds_nothing() -> Result<(), TestError> {
        let tmp = tempfile::tempdir().map_err(|e| format!("tmp: {e:?}"))?;
        let members = three();
        let path = write(tmp.path(), "set.7z", &build(&refs(&members), None, false)?)?;
        let walked = walk_file(&path, Some(&label_of(&path, "z.pcap")), &limits(), None)?;
        assert!(walked.out.members.is_empty(), "no member is written");
        assert_eq!(walked.entries, 3, "the archive entries this walk met");
        assert!(walked.out.stops.is_empty(), "{:?}", walked.out.stops);
        Ok(())
    }

    #[test]
    fn an_expansion_reads_every_block_in_order() -> Result<(), TestError> {
        let tmp = tempfile::tempdir().map_err(|e| format!("tmp: {e:?}"))?;
        let members = three();
        let path = write(tmp.path(), "set.7z", &build(&refs(&members), None, false)?)?;
        let walked = walk_file(&path, None, &limits(), None)?;
        assert_eq!(
            names(&path, &walked.out),
            ["a.pcap", "b.pcap", "c.pcap"],
            "the members written, in archive order"
        );
        assert_eq!(walked.entries, 3, "the archive entries this walk met");
        for (member, (_, bytes)) in walked.out.members.iter().zip(&members) {
            assert_eq!(
                &std::fs::read(&member.path).map_err(|e| format!("read: {e:?}"))?,
                bytes,
                "the extracted file holds the member's bytes"
            );
        }
        Ok(())
    }

    /// The found member's block is whole; a later block is damaged. Before
    /// the fix the later block was still decoded, so the walk reported the
    /// archive broken beside the member it had found.
    #[test]
    fn damage_after_the_found_member_is_never_read() -> Result<(), TestError> {
        let tmp = tempfile::tempdir().map_err(|e| format!("tmp: {e:?}"))?;
        let members = three();
        let whole = build(&refs(&members), None, false)?;
        let path = write(tmp.path(), "set.7z", &with_damaged_block(whole, None, 2)?)?;
        let walked = walk_file(&path, Some(&label_of(&path, "a.pcap")), &limits(), None)?;
        assert_eq!(
            names(&path, &walked.out),
            ["a.pcap"],
            "the members written, in archive order"
        );
        assert!(walked.out.stops.is_empty(), "{:?}", walked.out.stops);
        assert_eq!(
            std::fs::read(&walked.out.members[0].path).map_err(|e| format!("read: {e:?}"))?,
            members[0].1,
            "the extracted file holds the member's bytes"
        );
        Ok(())
    }

    /// With a password every error is taken as "wrong password", so the
    /// damaged later block un-found the member: the pointer answered that the
    /// archive held no such member, with the right password in the keyring.
    #[test]
    fn a_locked_7z_gives_the_found_member_whatever_follows_it() -> Result<(), TestError> {
        let tmp = tempfile::tempdir().map_err(|e| format!("tmp: {e:?}"))?;
        let members = three();
        for encrypt_header in [false, true] {
            for wanted in ["a.pcap", "b.pcap"] {
                let whole = build(&refs(&members), Some(secret("7z-stop")), encrypt_header)?;
                let path = write(
                    tmp.path(),
                    "locked.7z",
                    &with_damaged_block(whole, Some(secret("7z-stop")), 2)?,
                )?;
                let mut ring = ring_of(&[secret("7z-stop")])?;
                let found = extract_member_with(
                    &path,
                    &label_of(&path, wanted),
                    &limits(),
                    Some(&mut ring),
                )
                .map_err(|e| format!("header {encrypt_header}, {wanted}: {e}"))?;
                let Some((member, _dir)) = found else {
                    return Err(format!("header {encrypt_header}: {wanted} not found").into());
                };
                let bytes = &members
                    .iter()
                    .find(|(n, _)| *n == wanted)
                    .ok_or("member")?
                    .1;
                assert_eq!(
                    &std::fs::read(&member.path).map_err(|e| format!("read: {e:?}"))?,
                    bytes,
                    "the extracted file holds the member's bytes"
                );
                assert_eq!(
                    member.encryption,
                    Encryption::SevenZipAes256,
                    "the member carries the archive's encryption"
                );
            }
        }
        Ok(())
    }

    #[test]
    fn damage_before_the_wanted_member_is_still_reported() -> Result<(), TestError> {
        let tmp = tempfile::tempdir().map_err(|e| format!("tmp: {e:?}"))?;
        let members = three();
        let path = write(
            tmp.path(),
            "set.7z",
            &with_damaged_block(build(&refs(&members), None, false)?, None, 0)?,
        )?;
        let label = label_of(&path, "c.pcap");
        let Err(e) = extract_member_with(&path, &label, &limits(), None) else {
            return Err("a member behind a damaged block was returned".into());
        };
        assert!(e.to_string().contains("set.7z"), "{e}");
        Ok(())
    }

    #[test]
    fn an_expansion_reports_a_damaged_last_block_and_keeps_what_came_before()
    -> Result<(), TestError> {
        let tmp = tempfile::tempdir().map_err(|e| format!("tmp: {e:?}"))?;
        let members = three();
        let whole = build(&refs(&members), None, false)?;
        let path = write(tmp.path(), "set.7z", &with_damaged_block(whole, None, 2)?)?;
        let walked = walk_file(&path, None, &limits(), None)?;
        assert_eq!(
            names(&path, &walked.out),
            ["a.pcap", "b.pcap"],
            "the members written, in archive order"
        );
        assert!(
            matches!(walked.out.stops.as_slice(), [Stop::Broken { container, .. }]
                if *container == label_of(&path, "c.pcap")),
            "{:?}",
            walked.out.stops
        );
        Ok(())
    }

    /// The first member alone passes the inflation ceiling. One stop, naming
    /// that member, and no later block read.
    #[test]
    fn the_inflation_ceiling_is_reported_once_and_ends_the_read() -> Result<(), TestError> {
        let tmp = tempfile::tempdir().map_err(|e| format!("tmp: {e:?}"))?;
        let big = pcap_bytes(&[0x5a; 8192]);
        let small = three();
        let mut members = vec![("big.pcap", big)];
        members.extend(small);
        let path = write(tmp.path(), "cap.7z", &build(&refs(&members), None, false)?)?;
        let lim = limits_of(MAX_ENTRIES, 4096);
        let walked = walk_file(&path, None, &lim, None)?;
        assert!(
            walked.out.members.is_empty(),
            "{:?}",
            names(&path, &walked.out)
        );
        assert_eq!(
            walked.out.stops,
            vec![Stop::InflationCap {
                limit: 4096,
                at: label_of(&path, "big.pcap"),
            }],
            "the walk reports this one stop and no other"
        );
        assert_eq!(walked.entries, 1, "blocks after the ceiling were read");
        Ok(())
    }

    #[test]
    fn the_inflation_ceiling_in_the_last_member_keeps_the_earlier_ones() -> Result<(), TestError> {
        let tmp = tempfile::tempdir().map_err(|e| format!("tmp: {e:?}"))?;
        let mut members = three().to_vec();
        members.push(("big.pcap", pcap_bytes(&[0x5a; 8192])));
        let path = write(tmp.path(), "cap.7z", &build(&refs(&members), None, false)?)?;
        let lim = limits_of(MAX_ENTRIES, 4096);
        let walked = walk_file(&path, None, &lim, None)?;
        assert_eq!(
            names(&path, &walked.out),
            ["a.pcap", "b.pcap", "c.pcap"],
            "the members written, in archive order"
        );
        assert_eq!(
            walked.out.stops,
            vec![Stop::InflationCap {
                limit: 4096,
                at: label_of(&path, "big.pcap"),
            }],
            "the walk reports this one stop and no other"
        );
        Ok(())
    }

    /// A tar inside the 7z passes the entry cap, which stops the walk. The
    /// capture in the next block was still extracted: a member past the cap.
    #[test]
    fn no_member_is_extracted_after_the_entry_cap() -> Result<(), TestError> {
        let tmp = tempfile::tempdir().map_err(|e| format!("tmp: {e:?}"))?;
        let tar = tar_of(4);
        let after = pcap_bytes(b"after-the-cap");
        let path = write(
            tmp.path(),
            "cap.7z",
            &build(&[("four.tar", &tar), ("after.pcap", &after)], None, false)?,
        )?;
        let lim = limits_of(3, 64 * 1024 * 1024);
        let walked = walk_file(&path, None, &lim, None)?;
        assert_eq!(
            names(&path, &walked.out),
            ["four.tar/t0.pcap", "four.tar/t1.pcap"],
            "the members written, in archive order"
        );
        assert_eq!(
            walked.out.stops,
            vec![Stop::EntryCap { limit: 3 }],
            "the walk reports this one stop and no other"
        );
        Ok(())
    }

    /// The walk has stopped at the entry cap; the next block is a locked 7z.
    /// Before the fix it was opened and the operator was asked for its
    /// password, for an archive whose members could not be kept.
    #[test]
    fn no_password_is_asked_for_after_the_walk_has_stopped() -> Result<(), TestError> {
        let tmp = tempfile::tempdir().map_err(|e| format!("tmp: {e:?}"))?;
        let tar = tar_of(4);
        let locked = build(
            &[("in.pcap", &pcap_bytes(b"locked"))],
            Some(secret("7z-after-stop")),
            false,
        )?;
        let path = write(
            tmp.path(),
            "cap.7z",
            &build(&[("four.tar", &tar), ("locked.7z", &locked)], None, false)?,
        )?;
        let asked = std::sync::Arc::new(parking_lot::Mutex::new(Vec::new()));
        let mut ring = Keyring::default();
        ring.set_prompter(Some(Box::new(Recording(asked.clone()))));
        let lim = limits_of(3, 64 * 1024 * 1024);
        let walked = walk_file(&path, None, &lim, Some(&mut ring))?;
        assert_eq!(
            walked.out.stops,
            vec![Stop::EntryCap { limit: 3 }],
            "the walk reports this one stop and no other"
        );
        assert!(asked.lock().is_empty(), "asked: {:?}", asked.lock());
        assert!(walked.out.skipped.is_empty(), "{:?}", walked.out.skipped);
        Ok(())
    }

    /// The same archive under a cap it does not reach: the locked 7z is
    /// reached, and its password is asked for. This is what shows the test
    /// above is able to see a prompt.
    #[test]
    fn a_locked_7z_in_a_walk_that_goes_on_is_asked_about() -> Result<(), TestError> {
        let tmp = tempfile::tempdir().map_err(|e| format!("tmp: {e:?}"))?;
        let tar = tar_of(4);
        let locked = build(
            &[("in.pcap", &pcap_bytes(b"locked"))],
            Some(secret("7z-after-stop")),
            false,
        )?;
        let path = write(
            tmp.path(),
            "cap.7z",
            &build(&[("four.tar", &tar), ("locked.7z", &locked)], None, false)?,
        )?;
        let asked = std::sync::Arc::new(parking_lot::Mutex::new(Vec::new()));
        let mut ring = Keyring::default();
        ring.set_prompter(Some(Box::new(Recording(asked.clone()))));
        let walked = walk_file(&path, None, &limits(), Some(&mut ring))?;
        assert!(walked.out.stops.is_empty(), "{:?}", walked.out.stops);
        assert_eq!(asked.lock().len(), 1, "asked: {:?}", asked.lock());
        assert_eq!(walked.out.members.len(), 4, "the number of members written");
        Ok(())
    }

    /// The entry cap counts every archive of one input together. A 7z's
    /// members were counted and never compared with the cap, so a 7z inside
    /// another container could take the walk past it.
    #[test]
    fn a_7z_member_past_the_entry_cap_stops_the_walk() -> Result<(), TestError> {
        let tmp = tempfile::tempdir().map_err(|e| format!("tmp: {e:?}"))?;
        let members = three();
        let inner = build(&refs(&members), None, false)?;
        let after = pcap_bytes(b"after");
        let path = write(
            tmp.path(),
            "outer.tar",
            &build_tar(&[
                Spec::file("inner.7z", &inner),
                Spec::file("after.pcap", &after),
            ]),
        )?;
        // The tar entry is 1; a.pcap is 2, b.pcap is 3, c.pcap is 4. The
        // tar's second entry is never met: the stop is the tar's too.
        let walked = walk_file(&path, None, &limits_of(3, 64 * 1024 * 1024), None)?;
        assert_eq!(
            names(&path, &walked.out),
            ["inner.7z/a.pcap", "inner.7z/b.pcap"],
            "the members written, in archive order"
        );
        assert_eq!(
            walked.out.stops,
            vec![Stop::EntryCap { limit: 3 }],
            "the walk reports this one stop and no other"
        );
        assert_eq!(walked.entries, 4, "the archive entries this walk met");
        Ok(())
    }

    /// The cap is passed with blocks of the 7z still to come. It is reported
    /// once, and the later blocks are not met.
    #[test]
    fn the_entry_cap_inside_a_7z_is_reported_once() -> Result<(), TestError> {
        let tmp = tempfile::tempdir().map_err(|e| format!("tmp: {e:?}"))?;
        let mut members = three().to_vec();
        members.push(("d.pcap", pcap_bytes(b"delta-delta-delta")));
        let inner = build(&refs(&members), None, false)?;
        let (x, y) = (pcap_bytes(b"x-ray"), pcap_bytes(b"yankee"));
        let path = write(
            tmp.path(),
            "outer.tar",
            &build_tar(&[
                Spec::file("x.pcap", &x),
                Spec::file("y.pcap", &y),
                Spec::file("inner.7z", &inner),
            ]),
        )?;
        // x.pcap is 1, y.pcap is 2, the 7z is 3; a.pcap is 4, b.pcap is 5,
        // c.pcap is 6. d.pcap, in the block after it, is never counted.
        let walked = walk_file(&path, None, &limits_of(5, 64 * 1024 * 1024), None)?;
        assert_eq!(
            names(&path, &walked.out),
            ["x.pcap", "y.pcap", "inner.7z/a.pcap", "inner.7z/b.pcap"],
            "the members written, in archive order"
        );
        assert_eq!(
            walked.out.stops,
            vec![Stop::EntryCap { limit: 5 }],
            "the walk reports this one stop and no other"
        );
        assert_eq!(walked.entries, 6, "the archive entries this walk met");
        Ok(())
    }

    #[test]
    fn a_7z_that_ends_exactly_at_the_entry_cap_is_read_whole() -> Result<(), TestError> {
        let tmp = tempfile::tempdir().map_err(|e| format!("tmp: {e:?}"))?;
        let members = three();
        let inner = build(&refs(&members), None, false)?;
        let path = write(
            tmp.path(),
            "outer.tar",
            &build_tar(&[Spec::file("inner.7z", &inner)]),
        )?;
        let walked = walk_file(&path, None, &limits_of(4, 64 * 1024 * 1024), None)?;
        assert_eq!(walked.out.members.len(), 3, "the number of members written");
        assert!(walked.out.stops.is_empty(), "{:?}", walked.out.stops);
        Ok(())
    }

    /// A 7z that lists more entries than the cap is refused from its member
    /// list, before any block is decoded.
    #[test]
    fn a_7z_listing_more_entries_than_the_cap_is_refused_unread() -> Result<(), TestError> {
        let tmp = tempfile::tempdir().map_err(|e| format!("tmp: {e:?}"))?;
        let members = three();
        let path = write(tmp.path(), "set.7z", &build(&refs(&members), None, false)?)?;
        let walked = walk_file(&path, None, &limits_of(2, 64 * 1024 * 1024), None)?;
        assert!(walked.out.members.is_empty(), "no member is written");
        assert_eq!(
            walked.out.stops,
            vec![Stop::EntryCap { limit: 2 }],
            "the walk reports this one stop and no other"
        );
        assert_eq!(walked.entries, 0, "the archive entries this walk met");
        Ok(())
    }

    /// A stop inside a 7z stops the container that holds it too.
    #[test]
    fn a_stop_inside_a_nested_7z_stops_the_outer_tar() -> Result<(), TestError> {
        let tmp = tempfile::tempdir().map_err(|e| format!("tmp: {e:?}"))?;
        let big = pcap_bytes(&[0x5a; 8192]);
        let inner = build(&[("big.pcap", &big)], None, false)?;
        let after = pcap_bytes(b"after");
        let path = write(
            tmp.path(),
            "outer.tar",
            &build_tar(&[
                Spec::file("inner.7z", &inner),
                Spec::file("after.pcap", &after),
            ]),
        )?;
        let walked = walk_file(&path, None, &limits_of(MAX_ENTRIES, 4096), None)?;
        assert!(
            walked.out.members.is_empty(),
            "{:?}",
            names(&path, &walked.out)
        );
        assert_eq!(walked.out.stops.len(), 1, "{:?}", walked.out.stops);
        assert_eq!(walked.entries, 2, "the tar went on after its 7z stopped");
        Ok(())
    }

    /// Members with no bytes sit outside every block, and the crate visits
    /// them after the last block. A stopped walk does not meet them either.
    #[test]
    fn an_empty_member_after_the_found_one_is_not_visited() -> Result<(), TestError> {
        let tmp = tempfile::tempdir().map_err(|e| format!("tmp: {e:?}"))?;
        let a = pcap_bytes(b"alpha");
        let path = write(
            tmp.path(),
            "set.7z",
            &build(&[("a.pcap", &a), ("empty.txt", b"")], None, false)?,
        )?;
        let walked = walk_file(&path, Some(&label_of(&path, "a.pcap")), &limits(), None)?;
        assert_eq!(
            names(&path, &walked.out),
            ["a.pcap"],
            "the members written, in archive order"
        );
        assert_eq!(walked.entries, 1, "the archive entries this walk met");
        Ok(())
    }

    #[test]
    fn an_expansion_passes_over_an_empty_member() -> Result<(), TestError> {
        let tmp = tempfile::tempdir().map_err(|e| format!("tmp: {e:?}"))?;
        let (a, c) = (pcap_bytes(b"alpha"), pcap_bytes(b"charlie"));
        let path = write(
            tmp.path(),
            "set.7z",
            &build(
                &[("a.pcap", &a), ("empty.txt", b""), ("c.pcap", &c)],
                None,
                false,
            )?,
        )?;
        let walked = walk_file(&path, None, &limits(), None)?;
        assert_eq!(
            names(&path, &walked.out),
            ["a.pcap", "c.pcap"],
            "the members written, in archive order"
        );
        assert_eq!(walked.entries, 3, "the archive entries this walk met");
        assert!(walked.out.stops.is_empty(), "{:?}", walked.out.stops);
        Ok(())
    }

    /// One block holding every member, the layout the old call handled.
    #[test]
    fn a_solid_7z_stops_at_the_found_member_and_expands_whole() -> Result<(), TestError> {
        let tmp = tempfile::tempdir().map_err(|e| format!("tmp: {e:?}"))?;
        let members = three();
        let path = write(tmp.path(), "solid.7z", &build_solid(&refs(&members))?)?;
        let first = walk_file(&path, Some(&label_of(&path, "a.pcap")), &limits(), None)?;
        assert_eq!(
            names(&path, &first.out),
            ["a.pcap"],
            "the members written, in archive order"
        );
        assert_eq!(first.entries, 1, "the archive entries this walk met");
        let last = walk_file(&path, Some(&label_of(&path, "c.pcap")), &limits(), None)?;
        assert_eq!(
            names(&path, &last.out),
            ["c.pcap"],
            "the members written, in archive order"
        );
        assert_eq!(last.entries, 3, "the archive entries this walk met");
        let all = walk_file(&path, None, &limits(), None)?;
        assert_eq!(
            names(&path, &all.out),
            ["a.pcap", "b.pcap", "c.pcap"],
            "the members written, in archive order"
        );
        Ok(())
    }

    #[test]
    fn a_solid_7z_reports_the_inflation_ceiling_once() -> Result<(), TestError> {
        let tmp = tempfile::tempdir().map_err(|e| format!("tmp: {e:?}"))?;
        let big = pcap_bytes(&[0x5a; 8192]);
        let small = three();
        let mut members = vec![("big.pcap", big)];
        members.extend(small);
        let path = write(tmp.path(), "solid.7z", &build_solid(&refs(&members))?)?;
        let walked = walk_file(&path, None, &limits_of(MAX_ENTRIES, 4096), None)?;
        assert!(walked.out.members.is_empty(), "no member is written");
        assert_eq!(walked.out.stops.len(), 1, "{:?}", walked.out.stops);
        assert_eq!(walked.entries, 1, "the archive entries this walk met");
        Ok(())
    }

    /// A directory is an entry, as it is in a tar and a ZIP: it counts toward
    /// the entry cap. The crate visits directories after the last block.
    #[test]
    fn a_directory_in_a_7z_counts_toward_the_entry_cap() -> Result<(), TestError> {
        let tmp = tempfile::tempdir().map_err(|e| format!("tmp: {e:?}"))?;
        let (a, b) = (pcap_bytes(b"alpha"), pcap_bytes(b"bravo"));
        let inner = build(&[("a.pcap", &a), ("b.pcap", &b), ("d/", b"")], None, false)?;
        let path = write(
            tmp.path(),
            "outer.tar",
            &build_tar(&[Spec::file("inner.7z", &inner)]),
        )?;
        // The tar entry is 1; a.pcap is 2, b.pcap is 3, the directory is 4.
        let at_cap = walk_file(&path, None, &limits_of(4, 64 * 1024 * 1024), None)?;
        assert_eq!(at_cap.entries, 4, "the archive entries this walk met");
        assert_eq!(
            at_cap.out.directories, 1,
            "the directory entries counted as read"
        );
        assert!(at_cap.out.stops.is_empty(), "{:?}", at_cap.out.stops);
        let past = walk_file(&path, None, &limits_of(3, 64 * 1024 * 1024), None)?;
        assert_eq!(
            past.out.stops,
            vec![Stop::EntryCap { limit: 3 }],
            "the walk reports this one stop and no other"
        );
        assert_eq!(
            past.out.directories, 0,
            "the entry past the cap is not counted as read"
        );
        assert_eq!(past.out.members.len(), 2, "the number of members written");
        Ok(())
    }

    /// A password that fails is tried on the whole archive and rolled back.
    /// The entries its trial met are not charged to the cap: three members
    /// under a cap of three open with the fourth password tried.
    #[test]
    fn entries_met_by_a_wrong_password_do_not_count_toward_the_cap() -> Result<(), TestError> {
        let tmp = tempfile::tempdir().map_err(|e| format!("tmp: {e:?}"))?;
        let members = three();
        for encrypt_header in [false, true] {
            let path = write(
                tmp.path(),
                "locked.7z",
                &build(&refs(&members), Some(secret("7z-cap")), encrypt_header)?,
            )?;
            let mut ring = ring_of(&[
                secret("7z-cap-wrong-1"),
                secret("7z-cap-wrong-2"),
                secret("7z-cap-wrong-3"),
                secret("7z-cap"),
            ])?;
            let lim = limits_of(3, 64 * 1024 * 1024);
            let walked = walk_file(&path, None, &lim, Some(&mut ring))?;
            assert_eq!(
                names(&path, &walked.out),
                ["a.pcap", "b.pcap", "c.pcap"],
                "header {encrypt_header}: {:?} {:?}",
                walked.out.skipped,
                walked.out.stops
            );
            assert!(walked.out.stops.is_empty(), "{:?}", walked.out.stops);
            assert_eq!(walked.entries, 3, "header {encrypt_header}");
        }
        Ok(())
    }

    /// The one capture of the stored 7z the inflation-count tests read. A
    /// wrong password decrypts it to noise of the same size.
    fn stored_capture() -> Vec<u8> {
        pcap_bytes(&[0x5a; 4000])
    }

    /// A stored, AES-256 7z holding [`stored_capture`] as `a.pcap`, written
    /// under `dir`, locked with the password minted for `label`.
    fn stored_locked_7z(
        dir: &std::path::Path,
        label: &str,
    ) -> Result<std::path::PathBuf, TestError> {
        let a = stored_capture();
        write(
            dir,
            "stored.7z",
            &build_stored(&[("a.pcap", &a)], Some(secret(label)))?,
        )
    }

    /// FAILURE (ARCHIVE-TRIAL-INFLATION-COUNT): three wrong passwords each
    /// inflate the member to noise under the ceiling, and their sum passes
    /// it. Each trial is rolled back and returns its bytes, so the right
    /// password, tried fourth, still has the whole budget.
    #[test]
    fn wrong_7z_passwords_under_the_ceiling_leave_the_budget_to_the_right_one()
    -> Result<(), TestError> {
        let tmp = tempfile::tempdir().map_err(|e| format!("tmp: {e:?}"))?;
        let path = stored_locked_7z(tmp.path(), "7z-count")?;
        let size = stored_capture().len() as u64;
        let mut ring = ring_of(&[
            secret("7z-count-wrong-1"),
            secret("7z-count-wrong-2"),
            secret("7z-count-wrong-3"),
            secret("7z-count"),
        ])?;
        let walked = walk_file(
            &path,
            None,
            &limits_of(MAX_ENTRIES, 2 * size),
            Some(&mut ring),
        )?;
        assert!(
            walked.out.stops.is_empty(),
            "three rolled-back trials must not reach the ceiling: {:?}",
            walked.out.stops
        );
        assert_eq!(
            names(&path, &walked.out),
            ["a.pcap"],
            "the fourth password opens the member: {:?}",
            walked.out.skipped
        );
        assert_eq!(
            std::fs::read(&walked.out.members[0].path).map_err(|e| format!("read: {e:?}"))?,
            stored_capture(),
            "the member is the capture that was stored"
        );
        assert_eq!(ring.attempts(), 4, "every password was tried in order");
        Ok(())
    }

    /// EDGE, the boundary: the ceiling is exactly the member's size. A wrong
    /// password's trial ends exactly at the ceiling and is rolled back, and
    /// the right password then reads the member whole.
    #[test]
    fn a_wrong_7z_password_at_exactly_the_ceiling_leaves_room_for_the_right_one()
    -> Result<(), TestError> {
        let tmp = tempfile::tempdir().map_err(|e| format!("tmp: {e:?}"))?;
        let path = stored_locked_7z(tmp.path(), "7z-exact")?;
        let size = stored_capture().len() as u64;
        let mut ring = ring_of(&[secret("7z-exact-wrong"), secret("7z-exact")])?;
        let walked = walk_file(&path, None, &limits_of(MAX_ENTRIES, size), Some(&mut ring))?;
        assert!(
            walked.out.stops.is_empty(),
            "a member of exactly the ceiling is within it: {:?}",
            walked.out.stops
        );
        assert_eq!(
            names(&path, &walked.out),
            ["a.pcap"],
            "the second password opens the member: {:?}",
            walked.out.skipped
        );
        Ok(())
    }

    /// FAILURE: one password whose trial alone passes the ceiling. The trial
    /// cannot tell a wrong password from a right one on a member this large,
    /// so it is reported as the ceiling, the walk ends, nothing is kept and
    /// no later password is tried.
    #[test]
    fn a_7z_trial_that_alone_passes_the_ceiling_is_a_ceiling_stop() -> Result<(), TestError> {
        let tmp = tempfile::tempdir().map_err(|e| format!("tmp: {e:?}"))?;
        let path = stored_locked_7z(tmp.path(), "7z-over")?;
        let limit = stored_capture().len() as u64 - 1;
        let mut ring = ring_of(&[secret("7z-over-wrong"), secret("7z-over")])?;
        let walked = walk_file(&path, None, &limits_of(MAX_ENTRIES, limit), Some(&mut ring))?;
        assert_eq!(
            walked.out.stops,
            vec![Stop::InflationCap {
                limit,
                at: label_of(&path, "a.pcap"),
            }],
            "the walk reports the ceiling once, at the member"
        );
        assert!(
            walked.out.members.is_empty(),
            "nothing is kept: {:?}",
            names(&path, &walked.out)
        );
        assert_eq!(ring.attempts(), 1, "no password is tried after the stop");
        Ok(())
    }

    /// SUCCESS, unchanged: the right password first reads a member of exactly
    /// the ceiling, and an unencrypted stored 7z does the same with no
    /// password at all.
    #[test]
    fn the_right_7z_password_first_and_no_password_read_up_to_the_ceiling() -> Result<(), TestError>
    {
        let tmp = tempfile::tempdir().map_err(|e| format!("tmp: {e:?}"))?;
        let size = stored_capture().len() as u64;
        let lim = limits_of(MAX_ENTRIES, size);

        let locked = stored_locked_7z(tmp.path(), "7z-first")?;
        let mut ring = ring_of(&[secret("7z-first"), secret("7z-first-wrong")])?;
        let walked = walk_file(&locked, None, &lim, Some(&mut ring))?;
        assert_eq!(
            names(&locked, &walked.out),
            ["a.pcap"],
            "the first password opens the member: {:?} {:?}",
            walked.out.skipped,
            walked.out.stops
        );
        assert_eq!(ring.attempts(), 1, "the second password is never tried");

        let a = stored_capture();
        let open = write(
            tmp.path(),
            "open.7z",
            &build_stored(&[("a.pcap", &a)], None)?,
        )?;
        let walked = walk_file(&open, None, &lim, None)?;
        assert_eq!(
            names(&open, &walked.out),
            ["a.pcap"],
            "an unencrypted member of exactly the ceiling is read: {:?}",
            walked.out.stops
        );
        let walked = walk_file(&open, None, &limits_of(MAX_ENTRIES, size - 1), None)?;
        assert_eq!(
            walked.out.stops,
            vec![Stop::InflationCap {
                limit: size - 1,
                at: label_of(&open, "a.pcap"),
            }],
            "one byte under the member's size is still refused"
        );
        Ok(())
    }
}
