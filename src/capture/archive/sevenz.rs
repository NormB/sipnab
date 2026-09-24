// SPDX-License-Identifier: MIT OR Apache-2.0

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
//! hours. A refusal is `bound_exceeded (7z key derivation)` (Invariant 4).

use std::io::{self, Read, Seek};

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
        let mut flow = Flow::Continue;
        reader.for_each_entries(|entry, data| {
            if entry.is_directory() {
                if self.wanted.is_none() {
                    self.out.directories += 1;
                }
                return Ok(true);
            }
            self.entries += 1;
            let child = format!("{label}/{}", member_name(entry.name().as_bytes()));
            if !self.leads_to_wanted(&child) {
                // Solid blocks must be read through in order: drain, never skip.
                io::copy(data, &mut io::sink()).map_err(sevenz_rust2::Error::from)?;
                return Ok(true);
            }
            if !self.claim(&child) {
                self.skip(&child, SkipReason::DuplicateName);
                io::copy(data, &mut io::sink()).map_err(sevenz_rust2::Error::from)?;
                return Ok(true);
            }
            if let Some(keep) = self.keep {
                let file_name = child.rsplit('/').next().unwrap_or(&child);
                if !keep(file_name) {
                    self.out.filtered += 1;
                    io::copy(data, &mut io::sink()).map_err(sevenz_rust2::Error::from)?;
                    return Ok(true);
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
                return Ok(false);
            }
            Ok(true)
        })?;
        Ok(flow)
    }
}

#[cfg(test)]
pub(crate) mod testutil {
    //! Build 7z fixtures in a test, with the dev-only encoder. The password is
    //! always the caller's, minted at runtime.

    /// A 7z of `entries`, LZMA2, AES-256 with `password` when given; the
    /// member list encrypted too when `encrypt_header`.
    #[must_use]
    pub fn build(
        entries: &[(&str, &[u8])],
        password: Option<&str>,
        encrypt_header: bool,
    ) -> Vec<u8> {
        use sevenz_rust2::encoder_options::AesEncoderOptions;
        use sevenz_rust2::{ArchiveEntry, ArchiveWriter, EncoderMethod, Password};
        let mut w = ArchiveWriter::new(std::io::Cursor::new(Vec::new())).expect("writer");
        match password {
            Some(pw) => {
                w.set_content_methods(vec![
                    AesEncoderOptions::new(Password::from(pw)).into(),
                    EncoderMethod::LZMA2.into(),
                ]);
                w.set_encrypt_header(encrypt_header);
            }
            None => {
                w.set_content_methods(vec![EncoderMethod::LZMA2.into()]);
            }
        }
        for (name, data) in entries {
            w.push_archive_entry(ArchiveEntry::new_file(name), Some(*data))
                .expect("entry");
        }
        w.finish().expect("finish").into_inner()
    }

    /// `archive` with the NumCyclesPower of its header's AES coder raised to
    /// `power`, and the start header's checksums redone to match: an archive
    /// that asks for `2^power` key-derivation rounds.
    #[must_use]
    pub fn with_cycles_power(mut archive: Vec<u8>, power: u8) -> Vec<u8> {
        let id = [0x06u8, 0xF1, 0x07, 0x01];
        let at = archive
            .windows(4)
            .rposition(|w| w == id)
            .expect("an AES coder in the plain header");
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
    #[must_use]
    pub fn with_iv_first_byte(mut archive: Vec<u8>, value: u8) -> Vec<u8> {
        let id = [0x06u8, 0xF1, 0x07, 0x01];
        let at = archive
            .windows(4)
            .rposition(|w| w == id)
            .expect("an AES coder in the plain header");
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

    /// Redo the next-header CRC and the start header's CRC after a patch.
    fn refresh_checksums(mut archive: Vec<u8>) -> Vec<u8> {
        let next_offset = u64::from_le_bytes(archive[12..20].try_into().expect("8")) as usize;
        let next_size = u64::from_le_bytes(archive[20..28].try_into().expect("8")) as usize;
        let header = 32 + next_offset;
        let crc = crc32(&archive[header..header + next_size]);
        archive[28..32].copy_from_slice(&crc.to_le_bytes());
        let start = crc32(&archive[12..32]);
        archive[8..12].copy_from_slice(&start.to_le_bytes());
        archive
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
    use super::super::password::{ArchivePassword, Candidate, Keyring, Source};
    use super::super::tar::testutil::{Spec, build as build_tar};
    use super::super::*;
    use super::Declared;
    use super::testutil::{build, with_cycles_power, with_iv_first_byte};
    use std::io::{Read, Write};

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

    fn ring_of(passwords: &[&str]) -> Keyring {
        Keyring::new(
            passwords
                .iter()
                .map(|p| Candidate {
                    password: ArchivePassword::from_bytes(p.as_bytes()).expect("valid"),
                    source: Source::File,
                })
                .collect(),
            None,
        )
    }

    #[test]
    fn a_member_that_ends_before_its_declared_size_is_an_error() {
        let mut r = Declared::new(&b"abc"[..], 5);
        let mut out = Vec::new();
        let e = r.read_to_end(&mut out).expect_err("short");
        assert_eq!(e.kind(), io::ErrorKind::UnexpectedEof);
        assert_eq!(out, b"abc");
        assert!(e.to_string().contains("3 of 5"), "{e}");
    }

    #[test]
    fn a_member_of_exactly_its_declared_size_reads_clean() {
        let mut r = Declared::new(&b"abcde"[..], 5);
        let mut out = Vec::new();
        assert_eq!(r.read_to_end(&mut out).expect("exact"), 5);
        assert_eq!(r.read(&mut [0u8; 4]).expect("past the end"), 0);
    }

    #[test]
    fn an_empty_buffer_is_not_mistaken_for_the_end() {
        let mut r = Declared::new(&b"abc"[..], 3);
        assert_eq!(r.read(&mut []).expect("zero-length read"), 0);
        let mut out = Vec::new();
        assert_eq!(r.read_to_end(&mut out).expect("then the rest"), 3);
    }

    fn write(dir: &std::path::Path, name: &str, bytes: &[u8]) -> std::path::PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, bytes).expect("write");
        p
    }

    fn expand_with(path: &std::path::Path, keyring: Option<&mut Keyring>) -> Expansion {
        expand_filtered_with(path, &limits(), None, keyring).expect("expand")
    }

    #[test]
    fn an_unencrypted_7z_reads_like_a_tar() {
        let tmp = tempfile::tempdir().expect("tmp");
        let a = pcap_bytes(b"alpha");
        let path = write(
            tmp.path(),
            "set.7z",
            &build(&[("set/a.pcap", &a), ("notes.txt", b"lab")], None, false),
        );
        let exp = expand_with(&path, None);
        assert_eq!(exp.members.len(), 1, "{:?} {:?}", exp.skipped, exp.stops);
        assert_eq!(
            exp.members[0].label,
            format!("{}/set/a.pcap", path.display())
        );
        assert_eq!(exp.members[0].layers, vec![Layer::SevenZip]);
        assert_eq!(exp.members[0].encryption, Encryption::None);
        assert_eq!(std::fs::read(&exp.members[0].path).expect("read"), a);
    }

    #[test]
    fn an_aes_7z_opens_with_the_right_password_and_says_why_not_otherwise() {
        let tmp = tempfile::tempdir().expect("tmp");
        let a = pcap_bytes(b"secret");
        for encrypt_header in [false, true] {
            let path = write(
                tmp.path(),
                "aes.7z",
                &build(&[("a.pcap", &a)], Some(secret("7z-right")), encrypt_header),
            );
            let exp = expand_with(&path, Some(&mut ring_of(&["x", secret("7z-right")])));
            assert_eq!(
                exp.members.len(),
                1,
                "header {encrypt_header}: {:?}",
                exp.skipped
            );
            assert_eq!(exp.members[0].encryption, Encryption::SevenZipAes256);
            assert_eq!(std::fs::read(&exp.members[0].path).expect("read"), a);

            let exp = expand_with(&path, Some(&mut ring_of(&[secret("7z-wrong")])));
            assert!(exp.members.is_empty());
            assert!(
                matches!(exp.skipped.as_slice(), [s] if s.reason == SkipReason::EncryptedWrongPassword),
                "{:?} {:?}",
                exp.skipped,
                exp.stops
            );

            let exp = expand_with(&path, None);
            assert!(
                matches!(exp.skipped.as_slice(), [s] if s.reason == SkipReason::EncryptedNoPassword),
                "{:?}",
                exp.skipped
            );
        }
    }

    /// A wrong key decrypts to noise, and LZMA2 reads some noise without
    /// complaint: a first byte of 0x00 is its end-of-stream marker, so the
    /// member ends empty, and 0x01/0x02 open an uncompressed chunk that
    /// passes the noise through for the CRC to catch at the end. Neither may
    /// count as the password opening the archive. Every first byte is tried,
    /// so both cases are hit on every run rather than one run in ~100.
    #[test]
    fn no_first_decrypted_byte_lets_a_wrong_password_open_a_7z() {
        let tmp = tempfile::tempdir().expect("tmp");
        let a = pcap_bytes(b"every-first-byte");
        // Two key-derivation rounds instead of 2^19: the key no longer
        // matches what the content was encrypted with, which is the point.
        let base = with_cycles_power(build(&[("a.pcap", &a)], Some(secret("7z-iv")), false), 1);
        let mut opened = Vec::new();
        for value in 0..=u8::MAX {
            let path = write(
                tmp.path(),
                &format!("iv{value}.7z"),
                &with_iv_first_byte(base.clone(), value),
            );
            let exp = expand_with(&path, Some(&mut ring_of(&[secret("7z-iv-wrong")])));
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
    }

    #[test]
    fn a_decomposed_password_opens_a_7z_made_with_the_composed_one() {
        let tmp = tempfile::tempdir().expect("tmp");
        let base = secret("7z-nfc");
        let composed = format!("{}\u{00fc}{}", &base[..6], &base[6..12]);
        let decomposed = format!("{}u\u{0308}{}", &base[..6], &base[6..12]);
        let a = pcap_bytes(b"nfc");
        let path = write(
            tmp.path(),
            "nfc.7z",
            &build(&[("a.pcap", &a)], Some(&composed), false),
        );
        let mut keys = ring_of(&[&decomposed]);
        let exp = expand_with(&path, Some(&mut keys));
        assert_eq!(exp.members.len(), 1, "{:?}", exp.skipped);
        assert_eq!(keys.attempts(), 1, "every spelling is one attempt");
    }

    #[test]
    fn a_key_derivation_past_the_bound_is_refused_quickly() {
        let tmp = tempfile::tempdir().expect("tmp");
        let base = build(
            &[("a.pcap", &pcap_bytes(b"slow"))],
            Some(secret("7z-slow")),
            true,
        );
        let path = write(tmp.path(), "slow.7z", &with_cycles_power(base, 40));
        let started = std::time::Instant::now();
        let exp = expand_with(&path, Some(&mut ring_of(&[secret("7z-slow")])));
        assert!(started.elapsed() < std::time::Duration::from_secs(10));
        assert!(exp.members.is_empty());
        assert!(
            matches!(exp.skipped.as_slice(), [s] if s.reason.code() == "bound_exceeded"
                && s.reason.to_string().contains("7z key derivation")),
            "{:?} {:?}",
            exp.skipped,
            exp.stops
        );
    }

    #[test]
    fn a_password_7z_nested_in_a_tgz_opens() {
        let tmp = tempfile::tempdir().expect("tmp");
        let a = pcap_bytes(b"deep");
        let sz = build(&[("a.pcap", &a)], Some(secret("7z-nest")), false);
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(&build_tar(&[Spec::file("inner.7z", &sz)]))
            .expect("gzip");
        let path = write(tmp.path(), "outer.tgz", &gz.finish().expect("gzip"));
        let exp = expand_with(&path, Some(&mut ring_of(&[secret("7z-nest")])));
        assert_eq!(exp.members.len(), 1, "{:?} {:?}", exp.skipped, exp.stops);
        assert_eq!(
            exp.members[0].layers,
            vec![Layer::Gzip, Layer::Tar, Layer::SevenZip]
        );
    }
}
