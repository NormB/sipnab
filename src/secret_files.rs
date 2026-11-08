// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! Secret and credential files, read while the process still holds the
//! credentials and the root filesystem it started with.
//!
//! A run started as root drops to `--user` (or `nobody`) and may chroot first
//! (`bootstrap::confine_after_capture_start`). A file read after that point is
//! read as the dropped user, inside the new root. Signing keys, tokens, Basic
//! auth credentials, TLS private keys and the like are normally root-only
//! (`0600`), so a run that read them after the drop stopped with exit 2 on a
//! file the operator had protected correctly (OPS-11).
//!
//! The fix is one phase, not one patch per flag: [`SecretFiles::read_all`]
//! reads every file in [`bootstrap::secret_file_paths`] before the chroot and
//! the drop, and [`install`] makes the contents the answer that the readers
//! ([`read`], [`read_to_string`], [`mode`]) give for those paths from then on.
//! A path that was not read in that phase is read from disk, as before, so a
//! one-shot command that never drops (`--mint-token`) is unaffected.
//!
//! What is kept per file is what a reader would have seen at that moment: the
//! bytes, the permission bits (the world-readable refusals still apply, to the
//! mode the file had when it was read) and the error, when there was one. An
//! error is not reported here: the reader that needs the file reports it, with
//! the same text and the same exit code it always used, and a file nobody ends
//! up needing reports nothing.
//!
//! Only regular files are read in advance. A FIFO or a device (`<(pass show
//! key)`, `/dev/stdin`) can block an `open` and can be read only once, so it is
//! left to the reader that needs it, at the time it always read it.
//!
//! [`bootstrap::secret_file_paths`]: crate::app::bootstrap::secret_file_paths

//! The advance read and the store exist where a run can drop privileges:
//! the native, non-wasm builds that carry `crate::app`. Elsewhere the readers
//! read from disk, as they always did.

#[cfg(all(not(target_arch = "wasm32"), feature = "native"))]
use std::collections::HashMap;
use std::path::Path;
#[cfg(all(not(target_arch = "wasm32"), feature = "native"))]
use std::path::PathBuf;
#[cfg(all(not(target_arch = "wasm32"), feature = "native"))]
use std::sync::OnceLock;

#[cfg(all(not(target_arch = "wasm32"), feature = "native"))]
use parking_lot::Mutex;

/// One file as the advance read found it.
#[cfg(all(not(target_arch = "wasm32"), feature = "native"))]
#[derive(Debug, Clone)]
enum Entry {
    /// Read: the bytes and the permission bits at that moment.
    Read {
        /// The file's contents.
        bytes: Vec<u8>,
        /// `st_mode & 0o7777`, read by [`mode`] and [`advance`].
        mode: u32,
        /// The owner's uid (`st_uid`), or `0` where the platform has none.
        /// `privilege::read_private_file` judges the file by it.
        owner: u32,
    },
    /// The read failed. Kept as the OS error number when there was one, so a
    /// reader reports exactly the text it would have reported itself.
    Failed {
        /// `raw_os_error()`, when the error came from the OS.
        errno: Option<i32>,
        /// The kind, for an error that had no errno.
        kind: std::io::ErrorKind,
        /// The text, for an error that had no errno.
        text: String,
    },
}

#[cfg(all(not(target_arch = "wasm32"), feature = "native"))]
impl Entry {
    /// The stored error as an `io::Error`, or `None` for a file that was read.
    fn error(&self) -> Option<std::io::Error> {
        match self {
            Entry::Read { .. } => None,
            Entry::Failed {
                errno: Some(code), ..
            } => Some(std::io::Error::from_raw_os_error(*code)),
            Entry::Failed { kind, text, .. } => Some(std::io::Error::new(*kind, text.clone())),
        }
    }

    /// The stored error, for an entry known to be [`Entry::Failed`]; a
    /// generic error for one that was read, which no caller passes.
    fn into_error(self) -> std::io::Error {
        self.error()
            .unwrap_or_else(|| std::io::Error::other("the advance read found no error"))
    }

    /// The entry for an error.
    fn failed(e: &std::io::Error) -> Self {
        Entry::Failed {
            errno: e.raw_os_error(),
            kind: e.kind(),
            text: e.to_string(),
        }
    }
}

/// Files read in advance, by the path they were named with.
#[cfg(all(not(target_arch = "wasm32"), feature = "native"))]
#[derive(Debug, Default, Clone)]
pub struct SecretFiles {
    /// Path as named -> what reading it found.
    files: HashMap<PathBuf, Entry>,
}

#[cfg(all(not(target_arch = "wasm32"), feature = "native"))]
impl SecretFiles {
    /// Read every regular file in `paths` now.
    ///
    /// A path that is not a regular file is skipped (see the module docs);
    /// one that cannot be stat'd or read is kept as its error. Never fails:
    /// whether a missing file matters is for the reader that needs it.
    ///
    /// # Side effects
    ///
    /// Stats and reads each path.
    #[must_use]
    pub fn read_all<I>(paths: I) -> Self
    where
        I: IntoIterator<Item = PathBuf>,
    {
        let mut files = HashMap::new();
        for path in paths {
            if files.contains_key(&path) {
                continue;
            }
            let entry = match std::fs::metadata(&path) {
                Err(e) => Entry::failed(&e),
                Ok(meta) if !meta.is_file() => continue,
                Ok(meta) => match std::fs::read(&path) {
                    Ok(bytes) => Entry::Read {
                        bytes,
                        mode: permission_bits(&meta),
                        owner: owner_uid(&meta),
                    },
                    Err(e) => Entry::failed(&e),
                },
            };
            files.insert(path, entry);
        }
        SecretFiles { files }
    }

    /// The contents of `path` as read in advance, or `None` when it was not.
    ///
    /// # Errors
    ///
    /// The error the advance read met.
    #[cfg(test)]
    pub fn read(&self, path: &Path) -> Option<std::io::Result<Vec<u8>>> {
        let entry = self.files.get(path)?;
        Some(match entry {
            Entry::Read { bytes, .. } => Ok(bytes.clone()),
            Entry::Failed { .. } => Err(entry.error()?),
        })
    }

    /// The permission bits of `path` as read in advance, or `None` when it
    /// was not.
    ///
    /// # Errors
    ///
    /// The error the advance read met.
    #[cfg(test)]
    pub fn mode(&self, path: &Path) -> Option<std::io::Result<u32>> {
        let entry = self.files.get(path)?;
        Some(match entry {
            Entry::Read { mode, .. } => Ok(*mode),
            Entry::Failed { .. } => Err(entry.error()?),
        })
    }

    /// The owner of `path` as read in advance, or `None` when it was not.
    ///
    /// # Errors
    ///
    /// The error the advance read met.
    #[cfg(test)]
    pub fn owner(&self, path: &Path) -> Option<std::io::Result<u32>> {
        let entry = self.files.get(path)?;
        Some(match entry {
            Entry::Read { owner, .. } => Ok(*owner),
            Entry::Failed { .. } => Err(entry.error()?),
        })
    }
}

/// `st_uid`, or `0` where the platform has no Unix owner.
#[cfg(all(not(target_arch = "wasm32"), feature = "native"))]
fn owner_uid(meta: &std::fs::Metadata) -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        meta.uid()
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        0
    }
}

/// `st_mode & 0o7777`, or `0` where the platform has no Unix mode.
#[cfg(any(
    all(not(target_arch = "wasm32"), feature = "native"),
    feature = "hep",
    feature = "api",
    feature = "metrics"
))]
fn permission_bits(meta: &std::fs::Metadata) -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode() & 0o7777
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        0
    }
}

/// The files this process read before its privilege drop.
///
/// A map that [`install`] extends rather than a value set once: a production
/// run installs exactly once, and tests in one binary each install their own
/// uniquely named files without disturbing one another.
#[cfg(all(not(target_arch = "wasm32"), feature = "native"))]
static INSTALLED: OnceLock<Mutex<HashMap<PathBuf, Entry>>> = OnceLock::new();

/// Make `files` the answer for their paths, for the rest of the process.
#[cfg(all(not(target_arch = "wasm32"), feature = "native"))]
pub fn install(files: SecretFiles) {
    let map = INSTALLED.get_or_init(|| Mutex::new(HashMap::new()));
    map.lock().extend(files.files);
}

/// The installed entry for `path`, if any.
#[cfg(all(not(target_arch = "wasm32"), feature = "native"))]
fn installed(path: &Path) -> Option<Entry> {
    INSTALLED.get()?.lock().get(path).cloned()
}

/// A file as the advance read found it: what a reader that applies an
/// owner-dependent rule needs (`privilege::read_private_file`).
#[cfg(all(not(target_arch = "wasm32"), feature = "native"))]
#[derive(Debug)]
pub struct Advance {
    /// The file's contents.
    pub bytes: Vec<u8>,
    /// The owner's uid when it was read.
    pub owner: u32,
    /// `st_mode & 0o7777` when it was read.
    pub mode: u32,
}

/// The advance read of `path`, or `None` when it was not read in advance.
///
/// # Errors
///
/// The error the advance read met, as [`read`] gives it.
#[cfg(all(not(target_arch = "wasm32"), feature = "native"))]
#[must_use]
pub fn advance(path: &Path) -> Option<std::io::Result<Advance>> {
    let entry = installed(path)?;
    Some(match entry {
        Entry::Read { bytes, mode, owner } => Ok(Advance { bytes, owner, mode }),
        Entry::Failed { .. } => Err(entry.into_error()),
    })
}

/// The bytes of `path`: as read before the privilege drop when it was, from
/// disk otherwise.
///
/// # Errors
///
/// As [`std::fs::read`], or the error the advance read met.
pub fn read(path: &Path) -> std::io::Result<Vec<u8>> {
    #[cfg(all(not(target_arch = "wasm32"), feature = "native"))]
    if let Some(entry) = installed(path) {
        return match entry {
            Entry::Read { bytes, .. } => Ok(bytes),
            Entry::Failed { .. } => Err(entry.into_error()),
        };
    }
    std::fs::read(path)
}

/// [`read`] as UTF-8.
///
/// # Errors
///
/// As [`read`], or `InvalidData` when the bytes are not UTF-8 (the error
/// [`std::fs::read_to_string`] gives).
pub fn read_to_string(path: &Path) -> std::io::Result<String> {
    String::from_utf8(read(path)?).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "stream did not contain valid UTF-8",
        )
    })
}

/// The permission bits (`st_mode & 0o7777`) of `path`: as found before the
/// privilege drop when it was read then, from a `stat` now otherwise.
///
/// # Errors
///
/// As [`std::fs::metadata`], or the error the advance read met.
#[cfg(any(
    feature = "hep",
    feature = "api",
    feature = "metrics",
    feature = "vcon"
))]
pub fn mode(path: &Path) -> std::io::Result<u32> {
    if let Some(entry) = installed(path) {
        return match entry {
            Entry::Read { mode, .. } => Ok(mode),
            Entry::Failed { .. } => Err(entry.into_error()),
        };
    }
    std::fs::metadata(path).map(|m| permission_bits(&m))
}

#[cfg(all(test, unix, not(target_arch = "wasm32"), feature = "native"))]
mod tests {
    use super::*;
    type TestError = Box<dyn std::error::Error>;

    /// Read `name` with `bytes` and `mode` in `dir`, install it, then delete
    /// it: what is installed is all that is left to answer from.
    #[cfg(unix)]
    fn installed_then_removed(
        dir: &Path,
        name: &str,
        bytes: &[u8],
        mode: u32,
    ) -> Result<PathBuf, TestError> {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join(name);
        std::fs::write(&path, bytes)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))?;
        install(SecretFiles::read_all([path.clone()]));
        std::fs::remove_file(&path)?;
        Ok(path)
    }

    /// The advance read keeps the bytes, the mode and the error, and skips
    /// what is not a regular file.
    #[cfg(unix)]
    #[test]
    fn the_advance_read_keeps_bytes_mode_and_errors() -> Result<(), TestError> {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir()?;
        let file = dir.path().join("key");
        std::fs::write(&file, b"k\n")?;
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o640))?;
        let missing = dir.path().join("missing");
        let read = SecretFiles::read_all([file.clone(), missing.clone(), dir.path().to_path_buf()]);
        assert_eq!(
            read.read(&file).ok_or("file not read")??,
            b"k\n",
            "the bytes the file held"
        );
        assert_eq!(
            read.mode(&file).ok_or("file not read")??,
            0o640,
            "the permission bits the file had"
        );
        let err = read
            .read(&missing)
            .ok_or("missing file not kept")?
            .err()
            .ok_or("an error")?;
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound, "{err}");
        assert_eq!(
            err.to_string(),
            std::io::Error::from_raw_os_error(libc::ENOENT).to_string(),
            "the same text the reader would have reported"
        );
        assert!(
            read.read(dir.path()).is_none(),
            "a directory is left to its reader"
        );
        Ok(())
    }

    /// Once installed, the readers answer from the advance read, though the
    /// file is gone; an uninstalled path is read from disk.
    #[cfg(unix)]
    #[test]
    fn the_readers_answer_from_the_installed_read() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let path = installed_then_removed(dir.path(), "token", b"tok\n", 0o600)?;
        assert_eq!(read(&path)?, b"tok\n", "read answers from the store");
        assert_eq!(
            read_to_string(&path)?,
            "tok\n",
            "read_to_string answers from the store"
        );
        #[cfg(any(
            feature = "hep",
            feature = "api",
            feature = "metrics",
            feature = "vcon"
        ))]
        assert_eq!(mode(&path)?, 0o600, "mode answers from the store");
        let on_disk = dir.path().join("on-disk");
        std::fs::write(&on_disk, b"disk")?;
        assert_eq!(
            read(&on_disk)?,
            b"disk",
            "a path not read in advance is read now"
        );
        Ok(())
    }

    /// The file-or-inline secret resolver (`--metrics-auth-file`,
    /// `--hep-auth-file`) answers from the read made before the drop.
    #[cfg(unix)]
    #[test]
    fn the_named_secret_resolver_reads_through_the_store() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let path = installed_then_removed(dir.path(), "hep.auth", b"  shared  \n", 0o600)?;
        let got = crate::cli::resolve_named_secret(None, "--x", Some(&path), "--x-file")?;
        assert_eq!(
            got.as_deref(),
            Some("shared"),
            "the trimmed secret read before the drop"
        );
        Ok(())
    }

    /// A TLS private key read before the drop is used after it, and the
    /// world-readable refusal still applies, to the mode it had when read.
    #[cfg(all(unix, any(feature = "hep", feature = "api", feature = "metrics")))]
    #[test]
    fn a_tls_key_reads_through_the_store_and_keeps_its_refusal() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let pem = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/tls_rsa/key.pem"
        ))?;
        let private = installed_then_removed(dir.path(), "private.pem", &pem, 0o600)?;
        let loaded = crate::tls_files::pem_private_key(&private, "API TLS");
        assert!(
            loaded.is_ok(),
            "a 0600 key read before the drop loads: {:?}",
            loaded.err()
        );
        let open = installed_then_removed(dir.path(), "open.pem", &pem, 0o644)?;
        let err = crate::tls_files::pem_private_key(&open, "API TLS")
            .err()
            .ok_or("a world-readable key must be refused")?;
        assert!(
            format!("{err:#}").contains("world-readable (mode 0644)"),
            "{err:#}"
        );
        Ok(())
    }

    /// The `--srtp-keys`, `--tls-key` and `--redact-key-file`-style readers
    /// answer from the store too: here the SRTP key file parser.
    #[cfg(all(unix, feature = "tls"))]
    #[test]
    fn the_srtp_key_parser_reads_through_the_store() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let line = b"ssrc=1234 key=YUJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0\n";
        let path = installed_then_removed(dir.path(), "srtp.keys", line, 0o600)?;
        let entries = crate::rtp::srtp::parse_srtp_key_file(&path)?;
        assert_eq!(entries.len(), 1, "the one key line read before the drop");
        Ok(())
    }

    /// The `--tls-key` loader answers from the store.
    #[cfg(all(unix, feature = "tls"))]
    #[test]
    fn the_rsa_key_loader_reads_through_the_store() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let pem = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/tls_rsa/key.pem"
        ))?;
        let path = installed_then_removed(dir.path(), "rsa.pem", &pem, 0o600)?;
        let loaded = crate::capture::rsa_key::RsaKey::from_pem_file(&path);
        assert!(
            loaded.is_ok(),
            "the key read before the drop loads: {:?}",
            loaded.err()
        );
        Ok(())
    }

    /// Install one entry as if the advance read had found it: `owner` and
    /// `mode` as given, which a test cannot otherwise arrange for a uid it
    /// does not run as.
    #[cfg(feature = "vcon")]
    fn install_as_found(dir: &Path, name: &str, bytes: &[u8], owner: u32, mode: u32) -> PathBuf {
        let path = dir.join(name);
        let mut files = HashMap::new();
        files.insert(
            path.clone(),
            Entry::Read {
                bytes: bytes.to_vec(),
                mode,
                owner,
            },
        );
        install(SecretFiles { files });
        path
    }

    /// The advance read keeps the owner, which the private-file rule needs.
    #[test]
    fn the_advance_read_keeps_the_owner() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let file = dir.path().join("owned");
        std::fs::write(&file, b"x")?;
        let read = SecretFiles::read_all([file.clone()]);
        assert_eq!(
            read.owner(&file).ok_or("file not read")??,
            crate::privilege::current_uid(),
            "the file this test wrote is its own"
        );
        Ok(())
    }

    /// OPS-11, `[vcon_fetch] auth_file`: a credential read before the drop is
    /// what the fetcher uses after it, though the file can no longer be read.
    #[cfg(feature = "vcon")]
    #[test]
    fn a_vcon_fetch_credential_read_before_the_drop_is_used_after_it() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let path = installed_then_removed(
            dir.path(),
            "fetch.auth",
            b"Authorization: Bearer t0ken\n",
            0o600,
        )?;
        let header = crate::app::vcon_forward::AuthHeader::read_file_for(
            &path,
            "[vcon_fetch] auth_file",
            crate::app::vcon_forward::StoreKind::Generic,
        );
        assert!(
            header.is_ok(),
            "the credential read before the drop must be used: {:?}",
            header.err()
        );
        Ok(())
    }

    /// The private-file rule is unchanged by the advance read: the reader's
    /// own file that other users can read is refused, with the same text
    /// `privilege::open_private_file` gives.
    #[cfg(feature = "vcon")]
    #[test]
    fn a_credential_read_before_the_drop_keeps_the_private_file_rule() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let path = installed_then_removed(
            dir.path(),
            "open.auth",
            b"Authorization: Bearer t0ken\n",
            0o640,
        )?;
        let err = crate::app::vcon_forward::AuthHeader::read_file_for(
            &path,
            "[vcon_fetch] auth_file",
            crate::app::vcon_forward::StoreKind::Generic,
        )
        .err()
        .ok_or("a 0640 file of the reader's own must be refused")?;
        assert_eq!(
            err,
            format!(
                "[vcon_fetch] auth_file '{}' can be read or written by other users \
                 (mode 0640); chmod 600 it",
                path.display()
            ),
            "the advance read refuses a 0640 file with privilege::open_private_file's text"
        );
        Ok(())
    }

    /// The rule judges the file as the user reading it NOW: a file another
    /// user owns is accepted whatever its mode, as it was when the dropped
    /// user opened it itself. This is what keeps the accepted set the same
    /// for a root run, whose advance read runs as root.
    #[cfg(feature = "vcon")]
    #[test]
    fn a_credential_another_user_owns_is_judged_as_its_reader_would() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let other = crate::privilege::current_uid().wrapping_add(1);
        let path = install_as_found(
            dir.path(),
            "theirs.auth",
            b"Authorization: Bearer t0ken\n",
            other,
            0o644,
        );
        let header = crate::app::vcon_forward::AuthHeader::read_file_for(
            &path,
            "[vcon_fetch] auth_file",
            crate::app::vcon_forward::StoreKind::Generic,
        );
        assert!(
            header.is_ok(),
            "a file another user owns is its owner's decision: {:?}",
            header.err()
        );
        let mine = install_as_found(
            dir.path(),
            "mine.auth",
            b"Authorization: Bearer t0ken\n",
            crate::privilege::current_uid(),
            0o604,
        );
        let err = crate::app::vcon_forward::AuthHeader::read_file_for(
            &mine,
            "[vcon_fetch] auth_file",
            crate::app::vcon_forward::StoreKind::Generic,
        )
        .err()
        .ok_or("an others-readable file of the reader's own is refused")?;
        assert!(err.contains("(mode 0604)"), "{err}");
        Ok(())
    }

    /// A credential the advance read could not read reports what reading it
    /// would have reported, naming the setting and the path.
    #[cfg(feature = "vcon")]
    #[test]
    fn a_credential_the_advance_read_missed_reports_the_same_error() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("absent.auth");
        install(SecretFiles::read_all([path.clone()]));
        let err = crate::app::vcon_forward::AuthHeader::read_file_for(
            &path,
            "[vcon_fetch] auth_file",
            crate::app::vcon_forward::StoreKind::Generic,
        )
        .err()
        .ok_or("a missing credential is an error")?;
        assert_eq!(
            err,
            format!(
                "[vcon_fetch] auth_file '{}': {}",
                path.display(),
                std::io::Error::from_raw_os_error(libc::ENOENT)
            ),
            "a credential the advance read missed reports ENOENT, naming setting and path"
        );
        Ok(())
    }

    /// The size bound holds for a credential read in advance: one byte past
    /// `MAX_AUTH_FILE` is refused, and exactly that many is not refused for
    /// its size.
    #[cfg(feature = "vcon")]
    #[test]
    fn a_credential_read_before_the_drop_keeps_its_size_bound() -> Result<(), TestError> {
        use crate::app::vcon_forward::{AuthHeader, MAX_AUTH_FILE, StoreKind};
        let dir = tempfile::tempdir()?;
        let mut long = b"Authorization: Bearer ".to_vec();
        long.resize(MAX_AUTH_FILE + 1, b'a');
        let path = installed_then_removed(dir.path(), "long.auth", &long, 0o600)?;
        let err = AuthHeader::read_file_for(&path, "[vcon_fetch] auth_file", StoreKind::Generic)
            .err()
            .ok_or("an oversized credential is refused")?;
        assert!(
            err.contains(&format!("larger than {MAX_AUTH_FILE} bytes")),
            "{err}"
        );
        long.truncate(MAX_AUTH_FILE);
        let path = installed_then_removed(dir.path(), "edge.auth", &long, 0o600)?;
        let at_limit =
            AuthHeader::read_file_for(&path, "[vcon_fetch] auth_file", StoreKind::Generic);
        assert!(
            !at_limit
                .as_ref()
                .err()
                .is_some_and(|e| e.contains("larger than")),
            "exactly {MAX_AUTH_FILE} bytes is within the bound: {at_limit:?}"
        );
        Ok(())
    }

    /// OPS-11, `[vcon_fetch] decrypt_key`: the decryption key read before
    /// the drop loads after it.
    #[cfg(feature = "vcon")]
    #[test]
    fn a_decryption_key_read_before_the_drop_is_used_after_it() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let pem = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/vcon-jose/fake_grp.key"
        ))?;
        let path = installed_then_removed(dir.path(), "decrypt.pem", &pem, 0o600)?;
        let opener = crate::output::vcon_jose::Opener::load(&path);
        assert!(
            opener.is_ok(),
            "the key read before the drop must load: {:?}",
            opener.err()
        );
        Ok(())
    }

    /// The decryption key's own rule (owner-only, whoever owns it) applies to
    /// the mode the key had when it was read.
    #[cfg(feature = "vcon")]
    #[test]
    fn a_decryption_key_read_before_the_drop_keeps_its_mode_rule() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let pem = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/vcon-jose/fake_grp.key"
        ))?;
        let path = installed_then_removed(dir.path(), "group.pem", &pem, 0o640)?;
        let err = crate::output::vcon_jose::Opener::load(&path)
            .err()
            .ok_or("a group-readable decryption key is refused")?;
        assert!(
            err.contains("can be read by other users (mode 640)"),
            "{err}"
        );
        Ok(())
    }

    /// OPS-11, `[vcon_fetch] signer_ca`: the CA read before the drop is the
    /// one a decrypted container's signer is checked against.
    #[cfg(feature = "vcon")]
    #[test]
    fn a_signer_ca_read_before_the_drop_is_used_after_it() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let pem = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/vcon-jose/fake_ca_root.crt"
        ))?;
        let path = installed_then_removed(dir.path(), "signer.ca", &pem, 0o600)?;
        let ca = crate::app::vcon_fetch::signer_ca(
            &path,
            "[vcon_fetch] signer_ca",
            crate::settings::Origin::ConfigFile,
        );
        let trust = crate::app::vcon_fetch::signer_trust(Some(&ca), None);
        assert!(
            trust.is_ok(),
            "the CA read before the drop must load: {:?}",
            trust.err().map(|(_, e)| e)
        );
        Ok(())
    }

    /// `[vcon_fetch] ca` reaches the HTTPS client through the certificate
    /// reader, which already answers from the store.
    #[cfg(feature = "vcon")]
    #[test]
    fn a_fetch_ca_read_before_the_drop_is_used_after_it() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let pem = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/vcon-jose/fake_ca_root.crt"
        ))?;
        let path = installed_then_removed(dir.path(), "fetch.ca", &pem, 0o644)?;
        let config = crate::app::https_client::client_config(
            Some(&path),
            None,
            &crate::tls_files::TrustNames {
                ca: "[vcon_fetch] ca",
                extra: "[vcon_fetch] extra_ca",
                issuer: "the store's issuer",
            },
        );
        assert!(
            config.is_ok(),
            "the CA read before the drop must load: {:?}",
            config.err()
        );
        Ok(())
    }
}
