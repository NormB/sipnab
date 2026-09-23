// SPDX-License-Identifier: MIT OR Apache-2.0

//! ZIP archives, encrypted or not.
//!
//! A ZIP is read through its central directory, which needs a seekable file.
//! An archive named on the command line is opened where it lies. A ZIP found
//! INSIDE another layer, such as a tar or a gzip, is first copied into the
//! walk's private extraction directory, bounded by the inflation ceiling, and
//! read from there. That copy is still encrypted and compressed, and it is
//! deleted as soon as its members are walked.
//!
//! # Encrypted members
//!
//! Each encrypted member is offered to the [`Keyring`]: the password that
//! opened this archive before, then every configured candidate, then the
//! prompt. A wrong password is caught by the format's own check, which is the
//! ZipCrypto check byte or the AES verifier. ZipCrypto's check byte lets one
//! wrong password in 256 through. So a member opened with a password that has
//! not yet proven itself is read in TRIAL: if what comes out is not a capture
//! and its CRC or MAC fails, or the stream breaks, the trial is rolled back and
//! the next candidate is tried. The rollback removes every member, skip and
//! stop the trial recorded.

use std::io::{self, Read};

use super::password::{Container, Trial, Unlock};
use super::{Encryption, Flow, Inflating, Layer, SkipReason, Stop, Walker, member_name};

/// The archive a walk reads: a file it can seek in, and the copy to delete
/// after, when it had to make one.
pub(super) struct Seekable {
    /// The archive's bytes.
    pub(super) file: std::fs::File,
    /// The copy this walk made of a nested archive.
    spill: Option<std::path::PathBuf>,
}

impl Drop for Seekable {
    fn drop(&mut self) {
        if let Some(p) = self.spill.take() {
            let _ = std::fs::remove_file(p);
        }
    }
}

/// What one ZIP entry is, read from the central directory without a password.
struct EntryInfo {
    /// Its name, as a label component.
    name: String,
    /// A directory entry.
    is_dir: bool,
    /// A symbolic link.
    is_symlink: bool,
    /// Its encryption.
    encryption: Encryption,
}

impl Walker<'_> {
    /// Open the archive `label` names, from `src`, for reading by seeking.
    ///
    /// The archive the walk started from is reopened as a file. Anything
    /// nested is copied out first, into a file named for its `kind`.
    pub(super) fn seekable_source(
        &mut self,
        src: &mut dyn Read,
        label: &str,
        kind: &str,
    ) -> Result<Seekable, Flow> {
        if let Some(root) = self.root
            && label == self.root_label
        {
            return std::fs::File::open(root)
                .map(|file| Seekable { file, spill: None })
                .map_err(|e| self.broken(label, &e));
        }
        let dir = self.extract_dir().ok_or(Flow::Abort)?;
        self.spills += 1;
        let path = dir.join(format!("z{:05}.{kind}", self.spills));
        let copied = std::fs::OpenOptions::new()
            .write(true)
            .read(true)
            .create_new(true)
            .open(&path)
            .and_then(|mut f| {
                let limit = self.limits.max_inflated_bytes;
                let n = io::copy(&mut src.take(limit.saturating_add(1)), &mut f)?;
                if n > limit {
                    return Err(io::Error::other(super::CeilingReached));
                }
                Ok(f)
            });
        match copied {
            Ok(file) => Ok(Seekable {
                file,
                spill: Some(path),
            }),
            Err(e) => {
                let _ = std::fs::remove_file(&path);
                Err(self.broken(label, &e))
            }
        }
    }

    /// Walk the members of one ZIP archive.
    pub(super) fn walk_zip(
        &mut self,
        src: &mut dyn Read,
        label: &str,
        layers: &[Layer],
        depth: usize,
    ) -> Flow {
        let source = match self.seekable_source(src, label, "zip") {
            Ok(s) => s,
            Err(flow) => return flow,
        };
        let mut archive = match zip::ZipArchive::new(&source.file) {
            Ok(a) => a,
            Err(e) => {
                self.out.stops.push(Stop::Broken {
                    container: label.to_string(),
                    detail: e.to_string(),
                });
                return Flow::Continue;
            }
        };
        let infos = match entry_infos(&mut archive) {
            Ok(i) => i,
            Err(e) => {
                self.out.stops.push(Stop::Broken {
                    container: label.to_string(),
                    detail: e.to_string(),
                });
                return Flow::Continue;
            }
        };
        if infos.iter().any(|i| i.encryption == Encryption::ZipCrypto) {
            super::password::warn_zipcrypto_once(label);
        }
        for (index, info) in infos.into_iter().enumerate() {
            self.entries += 1;
            if self.entries > self.limits.max_entries {
                self.out.stops.push(Stop::EntryCap {
                    limit: self.limits.max_entries,
                });
                return Flow::Abort;
            }
            let child = format!("{label}/{}", info.name);
            if info.is_dir {
                if self.wanted.is_none() {
                    self.out.directories += 1;
                }
                continue;
            }
            if !self.leads_to_wanted(&child) {
                continue;
            }
            if info.is_symlink {
                self.skip_enc(&child, SkipReason::Link, info.encryption);
                continue;
            }
            if !self.claim(&child) {
                self.skip_enc(&child, SkipReason::DuplicateName, info.encryption);
                continue;
            }
            if let Some(keep) = self.keep {
                let file_name = child.rsplit('/').next().unwrap_or(&child);
                if !keep(file_name) {
                    self.out.filtered += 1;
                    continue;
                }
            }
            let mut next = layers.to_vec();
            next.push(Layer::Zip);
            let flow = if info.encryption == Encryption::None {
                self.read_plain(&mut archive, index, &child, &next, depth)
            } else {
                self.read_encrypted(
                    &mut archive,
                    index,
                    label,
                    &child,
                    &next,
                    depth,
                    info.encryption,
                )
            };
            if flow == Flow::Abort {
                return Flow::Abort;
            }
            if self.wanted.is_some() && !self.out.members.is_empty() {
                return Flow::Abort;
            }
        }
        Flow::Continue
    }

    /// Read an unencrypted member.
    fn read_plain(
        &mut self,
        archive: &mut zip::ZipArchive<&std::fs::File>,
        index: usize,
        child: &str,
        layers: &[Layer],
        depth: usize,
    ) -> Flow {
        match archive.by_index(index) {
            Ok(file) => {
                let mut inner = Inflating {
                    inner: file,
                    used: std::rc::Rc::clone(&self.used),
                    limit: self.limits.max_inflated_bytes,
                };
                self.walk(&mut inner, child, layers, depth)
            }
            Err(zip::result::ZipError::CompressionMethodNotSupported(m)) => {
                self.skip_enc(child, SkipReason::ZipMethod(m), Encryption::None);
                Flow::Continue
            }
            Err(e) => {
                let e = io::Error::other(e.to_string());
                self.broken(child, &e)
            }
        }
    }

    /// Read an encrypted member, offering it to the keyring.
    #[allow(clippy::too_many_arguments)]
    fn read_encrypted(
        &mut self,
        archive: &mut zip::ZipArchive<&std::fs::File>,
        index: usize,
        archive_label: &str,
        child: &str,
        layers: &[Layer],
        depth: usize,
        encryption: Encryption,
    ) -> Flow {
        let Some(keyring) = self.keyring.take() else {
            self.skip_enc(child, SkipReason::EncryptedNoPassword, encryption);
            return Flow::Continue;
        };
        let member = child
            .strip_prefix(archive_label)
            .map_or(child, |r| r.trim_start_matches('/'));
        let outer_encryption = self.encryption;
        self.encryption = encryption;
        let mut try_one = |password: &[u8]| -> Trial<Flow> {
            match archive.by_index_decrypt(index, password) {
                Err(zip::result::ZipError::InvalidPassword) => Trial::Wrong,
                Err(zip::result::ZipError::CompressionMethodNotSupported(m)) => {
                    Trial::Unsupported(format!("compression method {m}"))
                }
                Err(zip::result::ZipError::UnsupportedArchive(why)) => {
                    Trial::Unsupported(why.to_string())
                }
                Err(e) => Trial::Unsupported(e.to_string()),
                Ok(file) => {
                    let mut inner = Inflating {
                        inner: file,
                        used: std::rc::Rc::clone(&self.used),
                        limit: self.limits.max_inflated_bytes,
                    };
                    let mark = self.checkpoint();
                    let outer_trial = self.trial;
                    self.trial = true;
                    self.rejected = false;
                    let flow = self.walk(&mut inner, child, layers, depth);
                    self.trial = outer_trial;
                    if self.rejected || self.trial_broke(&mark) {
                        self.rejected = false;
                        self.rollback(mark);
                        Trial::Wrong
                    } else {
                        Trial::Opened(flow)
                    }
                }
            }
        };
        let outcome = keyring.unlock(archive_label, member, Container::Zip, &mut try_one);
        self.keyring = Some(keyring);
        self.encryption = outer_encryption;
        match outcome {
            Unlock::Opened(flow) => flow,
            Unlock::NoPassword => {
                self.skip_enc(child, SkipReason::EncryptedNoPassword, encryption);
                Flow::Continue
            }
            Unlock::WrongPassword => {
                self.skip_enc(child, SkipReason::EncryptedWrongPassword, encryption);
                Flow::Continue
            }
            Unlock::Unsupported(why) => {
                self.skip_enc(child, SkipReason::EncryptionUnsupported(why), encryption);
                Flow::Continue
            }
        }
    }
}

/// What every entry of `archive` is, from the central directory alone.
fn entry_infos(
    archive: &mut zip::ZipArchive<&std::fs::File>,
) -> zip::result::ZipResult<Vec<EntryInfo>> {
    let mut out = Vec::with_capacity(archive.len());
    for index in 0..archive.len() {
        let (name, is_dir, is_symlink, encrypted) = {
            let raw = archive.by_index_raw(index)?;
            (
                member_name(raw.name().as_bytes()),
                raw.is_dir(),
                raw.is_symlink(),
                raw.encrypted(),
            )
        };
        let encryption = if !encrypted {
            Encryption::None
        } else {
            match archive.get_aes_verification_key_and_salt(index)? {
                None => Encryption::ZipCrypto,
                Some(info) => match info.aes_mode {
                    zip::AesMode::Aes128 => Encryption::Aes128,
                    zip::AesMode::Aes192 => Encryption::Aes192,
                    zip::AesMode::Aes256 => Encryption::Aes256,
                },
            }
        };
        out.push(EntryInfo {
            name,
            is_dir,
            is_symlink,
            encryption,
        });
    }
    Ok(out)
}

/// Whether the ZIP at `path` holds an encrypted member, judged from its
/// central directory alone: no password is tried, so a listing that asks this
/// can never become a guessing loop.
///
/// # Errors
///
/// When the file cannot be opened or is not a readable ZIP.
pub fn has_encrypted_members(path: &std::path::Path) -> io::Result<bool> {
    let file = std::fs::File::open(path)?;
    let mut archive = zip::ZipArchive::new(&file).map_err(|e| io::Error::other(e.to_string()))?;
    for index in 0..archive.len() {
        let raw = archive
            .by_index_raw(index)
            .map_err(|e| io::Error::other(e.to_string()))?;
        if raw.encrypted() {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(test)]
pub(crate) mod testutil {
    //! Build ZIP fixtures in a test. The password is always the caller's:
    //! minted at runtime, never written in a source file.

    use std::io::Write;

    /// How to encrypt a fixture's members.
    #[derive(Clone, Copy)]
    pub enum Lock<'a> {
        /// Not at all.
        None,
        /// With ZipCrypto.
        ZipCrypto(&'a [u8]),
        /// With WinZip AES.
        Aes(zip::AesMode, &'a [u8]),
    }

    /// A ZIP holding `entries`, each encrypted per `lock`, deflated.
    #[must_use]
    pub fn build(entries: &[(&str, &[u8])], lock: Lock<'_>) -> Vec<u8> {
        build_each(
            &entries
                .iter()
                .map(|(n, d)| (*n, *d, lock))
                .collect::<Vec<_>>(),
        )
    }

    /// A ZIP holding `entries`, each with its own lock, deflated.
    #[must_use]
    pub fn build_each(entries: &[(&str, &[u8], Lock<'_>)]) -> Vec<u8> {
        build_with(entries, zip::CompressionMethod::Deflated)
    }

    /// A ZIP holding `entries`, each encrypted per `lock`, stored without
    /// compression.
    #[must_use]
    pub fn build_stored(entries: &[(&str, &[u8])], lock: Lock<'_>) -> Vec<u8> {
        build_with(
            &entries
                .iter()
                .map(|(n, d)| (*n, *d, lock))
                .collect::<Vec<_>>(),
            zip::CompressionMethod::Stored,
        )
    }

    /// A ZIP holding `entries`, each with its own lock, compressed per
    /// `method`.
    fn build_with(entries: &[(&str, &[u8], Lock<'_>)], method: zip::CompressionMethod) -> Vec<u8> {
        use zip::unstable::write::FileOptionsExt;
        let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        for (name, data, lock) in entries {
            let base = zip::write::SimpleFileOptions::default().compression_method(method);
            let opts = match lock {
                Lock::None => base,
                Lock::ZipCrypto(pw) => base.with_deprecated_encryption(pw).expect("zipcrypto"),
                Lock::Aes(mode, pw) => base.with_aes_encryption_bytes(*mode, pw),
            };
            w.start_file(*name, opts).expect("start");
            w.write_all(data).expect("write");
        }
        w.finish().expect("finish").into_inner()
    }
}

#[cfg(test)]
mod tests {
    use super::super::password::{ArchivePassword, Candidate, Keyring, Source};
    use super::super::tar::testutil::{Spec, build as build_tar};
    use super::super::*;
    use super::testutil::{Lock, build, build_each, build_stored};
    use std::io::Write;

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

    fn secret(label: &str) -> &'static [u8] {
        crate::test_material::key_str(label).as_bytes()
    }

    fn ring(labels: &[&str]) -> Keyring {
        Keyring::new(
            labels
                .iter()
                .map(|l| Candidate {
                    password: ArchivePassword::from_bytes(secret(l)).expect("valid"),
                    source: Source::File,
                })
                .collect(),
            None,
        )
    }

    fn write(dir: &std::path::Path, name: &str, bytes: &[u8]) -> std::path::PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, bytes).expect("write");
        p
    }

    fn expand_with(path: &std::path::Path, keyring: Option<&mut Keyring>) -> Expansion {
        expand_filtered_with(path, &limits(), None, keyring).expect("expand")
    }

    fn reasons(exp: &Expansion) -> Vec<(String, SkipReason)> {
        exp.skipped
            .iter()
            .map(|s| {
                (
                    s.label.rsplit('/').next().unwrap_or("").to_string(),
                    s.reason.clone(),
                )
            })
            .collect()
    }

    #[test]
    fn an_unencrypted_zip_reads_like_a_tar() {
        let tmp = tempfile::tempdir().expect("tmp");
        let a = pcap_bytes(b"alpha");
        let zip = build(&[("set/a.pcap", &a), ("README.txt", b"notes")], Lock::None);
        let path = write(tmp.path(), "set.zip", &zip);
        let exp = expand_with(&path, None);
        assert_eq!(exp.members.len(), 1, "{:?}", exp.skipped);
        assert_eq!(
            exp.members[0].label,
            format!("{}/set/a.pcap", path.display())
        );
        assert_eq!(exp.members[0].layers, vec![Layer::Zip]);
        assert_eq!(exp.members[0].encryption, Encryption::None);
        assert_eq!(std::fs::read(&exp.members[0].path).expect("read"), a);
        assert!(matches!(
            reasons(&exp).as_slice(),
            [(n, SkipReason::NotACapture { .. })] if n == "README.txt"
        ));
    }

    #[test]
    fn an_aes_zip_opens_with_the_right_password_and_says_why_not_otherwise() {
        let tmp = tempfile::tempdir().expect("tmp");
        let a = pcap_bytes(b"secret call");
        for (mode, want) in [
            (zip::AesMode::Aes128, Encryption::Aes128),
            (zip::AesMode::Aes192, Encryption::Aes192),
            (zip::AesMode::Aes256, Encryption::Aes256),
        ] {
            let zip = build(&[("a.pcap", &a)], Lock::Aes(mode, secret("aes-right")));
            let path = write(tmp.path(), "aes.zip", &zip);

            let mut right = ring(&["aes-right"]);
            let exp = expand_with(&path, Some(&mut right));
            assert_eq!(exp.members.len(), 1, "{:?}", exp.skipped);
            assert_eq!(exp.members[0].encryption, want);
            assert_eq!(std::fs::read(&exp.members[0].path).expect("read"), a);

            let mut wrong = ring(&["aes-wrong"]);
            let exp = expand_with(&path, Some(&mut wrong));
            assert!(exp.members.is_empty());
            assert_eq!(
                reasons(&exp),
                vec![("a.pcap".to_string(), SkipReason::EncryptedWrongPassword)]
            );
            assert_eq!(exp.skipped[0].encryption, want);

            let exp = expand_with(&path, None);
            assert_eq!(
                reasons(&exp),
                vec![("a.pcap".to_string(), SkipReason::EncryptedNoPassword)]
            );
        }
    }

    #[test]
    fn a_zipcrypto_zip_opens_with_the_second_candidate() {
        let tmp = tempfile::tempdir().expect("tmp");
        let a = pcap_bytes(b"legacy");
        let zip = build(&[("a.pcap", &a)], Lock::ZipCrypto(secret("zc-right")));
        let path = write(tmp.path(), "zc.zip", &zip);
        let mut keys = ring(&["zc-wrong", "zc-right"]);
        let exp = expand_with(&path, Some(&mut keys));
        assert_eq!(exp.members.len(), 1, "{:?}", exp.skipped);
        assert_eq!(exp.members[0].encryption, Encryption::ZipCrypto);
        assert_eq!(std::fs::read(&exp.members[0].path).expect("read"), a);
        assert_eq!(keys.attempts(), 2);
    }

    #[test]
    fn a_password_zip_holding_a_gzipped_capture_opens() {
        let tmp = tempfile::tempdir().expect("tmp");
        let a = pcap_bytes(b"inside gz");
        let zip = build(
            &[("a.pcap.gz", &gzip(&a))],
            Lock::Aes(zip::AesMode::Aes256, secret("gz")),
        );
        let path = write(tmp.path(), "gz.zip", &zip);
        let exp = expand_with(&path, Some(&mut ring(&["gz"])));
        assert_eq!(exp.members.len(), 1, "{:?}", exp.skipped);
        assert_eq!(exp.members[0].layers, vec![Layer::Zip, Layer::Gzip]);
        assert_eq!(std::fs::read(&exp.members[0].path).expect("read"), a);
    }

    #[test]
    fn a_password_zip_nested_in_a_tgz_opens_and_its_copy_is_removed() {
        let tmp = tempfile::tempdir().expect("tmp");
        let a = pcap_bytes(b"deep");
        let zip = build(
            &[("a.pcap", &a)],
            Lock::Aes(zip::AesMode::Aes256, secret("n")),
        );
        let tgz = gzip(&build_tar(&[Spec::file("inner.zip", &zip)]));
        let path = write(tmp.path(), "outer.tgz", &tgz);
        let exp = expand_with(&path, Some(&mut ring(&["n"])));
        assert_eq!(exp.members.len(), 1, "{:?} {:?}", exp.skipped, exp.stops);
        assert_eq!(
            exp.members[0].label,
            format!("{}/inner.zip/a.pcap", path.display())
        );
        assert_eq!(
            exp.members[0].layers,
            vec![Layer::Gzip, Layer::Tar, Layer::Zip]
        );
        let dir = exp.members[0].path.parent().expect("dir");
        let zips: Vec<_> = std::fs::read_dir(dir)
            .expect("ls")
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().ends_with(".zip"))
            .collect();
        assert!(zips.is_empty(), "the nested archive's copy is removed");
    }

    #[test]
    fn a_nested_bomb_inside_a_password_zip_is_refused() {
        let tmp = tempfile::tempdir().expect("tmp");
        // A capture header, then four megabytes of zeros: a bomb that reads
        // as a capture all the way to the ceiling.
        let mut payload = pcap_bytes(b"");
        payload.resize(4 * 1024 * 1024, 0);
        let bomb = gzip(&payload);
        let zip = build(
            &[("bomb.pcap.gz", &bomb)],
            Lock::Aes(zip::AesMode::Aes256, secret("bomb")),
        );
        let path = write(tmp.path(), "bomb.zip", &zip);
        let small = Limits {
            max_inflated_bytes: 1024 * 1024,
            ..limits()
        };
        let exp =
            expand_filtered_with(&path, &small, None, Some(&mut ring(&["bomb"]))).expect("expand");
        assert!(exp.members.is_empty());
        assert!(
            matches!(exp.stops.as_slice(), [Stop::InflationCap { .. }]),
            "{:?} {:?}",
            exp.stops,
            exp.skipped
        );
    }

    /// A wrong password that passes ZipCrypto's one-byte check: found by
    /// trying runtime-minted candidates until the check lets one through,
    /// which takes about 256 tries.
    fn false_positive(zip: &[u8]) -> Vec<u8> {
        let mut archive = zip::ZipArchive::new(std::io::Cursor::new(zip)).expect("zip");
        for i in 0..100_000u32 {
            let candidate = format!("{}{i}", crate::test_material::key_str("fp-probe"));
            if archive.by_index_decrypt(0, candidate.as_bytes()).is_ok() {
                return candidate.into_bytes();
            }
        }
        panic!("no false positive in 100000 tries: the check byte is not one byte");
    }

    #[test]
    fn a_zipcrypto_false_positive_is_caught_and_the_next_candidate_tried() {
        let a = pcap_bytes(&[7u8; 600]);
        // Deflated, a false positive's garbage breaks the inflater at once.
        false_positive_case(
            &build(&[("a.pcap", &a)], Lock::ZipCrypto(secret("fp-right"))),
            &a,
        );
        // Stored, the garbage reads cleanly and only the CRC at the member's
        // end gives it away.
        false_positive_case(
            &build_stored(&[("a.pcap", &a)], Lock::ZipCrypto(secret("fp-right"))),
            &a,
        );
    }

    fn false_positive_case(zip: &[u8], a: &[u8]) {
        let tmp = tempfile::tempdir().expect("tmp");
        let path = write(tmp.path(), "fp.zip", zip);
        let fp = false_positive(zip);
        let fp_candidate = || Candidate {
            password: ArchivePassword::from_bytes(&fp).expect("valid"),
            source: Source::File,
        };

        let mut only_fp = Keyring::new(vec![fp_candidate()], None);
        let exp = expand_with(&path, Some(&mut only_fp));
        assert!(exp.members.is_empty(), "a false positive must not be read");
        assert_eq!(
            reasons(&exp),
            vec![("a.pcap".to_string(), SkipReason::EncryptedWrongPassword)]
        );
        assert!(
            exp.stops.is_empty(),
            "the trial left nothing behind: {:?}",
            exp.stops
        );

        let mut both = Keyring::new(
            vec![
                fp_candidate(),
                Candidate {
                    password: ArchivePassword::from_bytes(secret("fp-right")).expect("valid"),
                    source: Source::File,
                },
            ],
            None,
        );
        let exp = expand_with(&path, Some(&mut both));
        assert_eq!(exp.members.len(), 1, "{:?}", exp.skipped);
        assert_eq!(std::fs::read(&exp.members[0].path).expect("read"), a);
        assert_eq!(both.attempts(), 2);
    }

    #[test]
    fn each_member_is_offered_its_archive_s_remembered_password_first() {
        let tmp = tempfile::tempdir().expect("tmp");
        let a = pcap_bytes(b"one");
        let b = pcap_bytes(b"two");
        let zip = build(
            &[("a.pcap", &a), ("b.pcap", &b)],
            Lock::Aes(zip::AesMode::Aes256, secret("mem-right")),
        );
        let path = write(tmp.path(), "two.zip", &zip);
        let mut keys = ring(&["mem-w1", "mem-w2", "mem-right"]);
        let exp = expand_with(&path, Some(&mut keys));
        assert_eq!(exp.members.len(), 2, "{:?}", exp.skipped);
        // Three for the first member, one for the second.
        assert_eq!(keys.attempts(), 4);
    }

    #[test]
    fn mixed_members_are_each_accounted_for() {
        let tmp = tempfile::tempdir().expect("tmp");
        let a = pcap_bytes(b"open");
        let b = pcap_bytes(b"locked");
        let zip = build_each(&[
            ("a.pcap", &a, Lock::None),
            (
                "b.pcap",
                &b,
                Lock::Aes(zip::AesMode::Aes256, secret("mixed")),
            ),
        ]);
        let path = write(tmp.path(), "mixed.zip", &zip);
        let exp = expand_with(&path, None);
        assert_eq!(exp.members.len(), 1);
        assert_eq!(
            reasons(&exp),
            vec![("b.pcap".to_string(), SkipReason::EncryptedNoPassword)]
        );
        assert_eq!(
            SkipReason::EncryptedNoPassword.code(),
            "encrypted_no_password"
        );
        assert_eq!(
            SkipReason::EncryptedWrongPassword.code(),
            "encrypted_wrong_password"
        );
    }

    #[test]
    fn extract_member_follows_a_label_into_a_password_zip() {
        let tmp = tempfile::tempdir().expect("tmp");
        let a = pcap_bytes(b"pointer");
        let zip = build(
            &[("d/a.pcap", &a)],
            Lock::Aes(zip::AesMode::Aes256, secret("ptr")),
        );
        let path = write(tmp.path(), "ptr.zip", &zip);
        let label = format!("{}/d/a.pcap", path.display());
        let (member, _dir) =
            extract_member_with(&path, &label, &limits(), Some(&mut ring(&["ptr"])))
                .expect("walk")
                .expect("found");
        assert_eq!(std::fs::read(&member.path).expect("read"), a);
    }

    /// A decrypted member lands in a file only its owner can read, whatever
    /// the umask: the directory's 0700 is not the only line.
    #[cfg(unix)]
    #[test]
    fn a_decrypted_member_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().expect("tmp");
        let zip = build(
            &[("a.pcap", &pcap_bytes(b"m"))],
            Lock::Aes(zip::AesMode::Aes256, secret("mode")),
        );
        let path = write(tmp.path(), "mode.zip", &zip);
        let exp = expand_with(&path, Some(&mut ring(&["mode"])));
        let mode = std::fs::metadata(&exp.members[0].path)
            .expect("stat")
            .permissions()
            .mode();
        assert_eq!(mode & 0o077, 0, "mode {:o}", mode & 0o777);
    }

    #[test]
    fn listing_marks_encryption_from_headers_alone() {
        let tmp = tempfile::tempdir().expect("tmp");
        let locked = write(
            tmp.path(),
            "l.zip",
            &build(
                &[("a.pcap", b"x")],
                Lock::Aes(zip::AesMode::Aes256, secret("l")),
            ),
        );
        let open = write(tmp.path(), "o.zip", &build(&[("a.pcap", b"x")], Lock::None));
        assert!(super::has_encrypted_members(&locked).expect("read"));
        assert!(!super::has_encrypted_members(&open).expect("read"));
    }
}
