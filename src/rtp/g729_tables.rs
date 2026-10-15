// SPDX-License-Identifier: MIT OR Apache-2.0
//! Where the G.729 codebook tables come from, and whether this run has them.
//!
//! sipnab ships no ITU-T table values (docs/g729.md). The decoder in the
//! `g729` crate takes its trained codebooks from a table file that
//! `sipnab g729 install` builds on each host from the ITU-T G.729 software
//! package. This module finds that file and loads it once per process:
//!
//! 1. `--g729-tables PATH`,
//! 2. else `[g729] tables` in the config file,
//! 3. else `g729-tables.bin` in the directory that holds the user's config
//!    file (`$XDG_CONFIG_HOME/sipnab`, else `~/.config/sipnab`; see
//!    [`crate::config::user_config_file`]).
//!
//! A path given by the flag or the key is used as given: a missing file there
//! is "not installed", never a fall-back to the next place. The loader checks
//! the layout and the pinned sha256 of the values, so a file that is not the
//! tables is refused with both hashes named.

use std::path::{Path, PathBuf};

/// The table file's name in the default directory.
pub const TABLE_FILE_NAME: &str = "g729-tables.bin";

/// Why a G.729 stream is not decoded when the tables are not installed. Also
/// the omission a vCon and an export summary record for the stream.
pub const NOT_INSTALLED: &str =
    "G.729 not decoded: codebook tables not installed; run sipnab g729 install";

/// Why a G.729 stream is not decoded by a build without the `g729` feature.
pub const NOT_BUILT: &str = "G.729 not decoded: this sipnab was built without the g729 feature";

/// Print `why` on stderr the first time this run fails to decode G.729.
///
/// A run that meets G.729 audio it cannot decode still exits 0, because the
/// rest of its work succeeded, and the vCon or export note that records the
/// omission is easy to miss. One line per run names the reason and the
/// command, whatever the verbosity.
pub fn say_once_not_decoded(why: &str) {
    static SAID: std::sync::Once = std::sync::Once::new();
    SAID.call_once(|| {
        stderr_line!("{why}");
    });
}

/// Where the table file is looked for, in the order this module's docs give.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TableLocation {
    /// `--g729-tables`.
    pub flag: Option<PathBuf>,
    /// `[g729] tables`.
    pub key: Option<PathBuf>,
    /// The default file, `g729-tables.bin` beside the user's config file.
    pub default: Option<PathBuf>,
}

impl TableLocation {
    /// The file to read: the flag's, else the key's, else the default.
    #[must_use]
    pub fn path(&self) -> Option<&Path> {
        self.flag
            .as_deref()
            .or(self.key.as_deref())
            .or(self.default.as_deref())
    }
}

/// The default table file, given `$HOME` and `$XDG_CONFIG_HOME`: the
/// directory [`crate::config::user_config_file`] names, with
/// [`TABLE_FILE_NAME`] in it. `None` when neither variable names a directory.
#[must_use]
pub fn default_table_file(home: Option<&Path>, xdg: Option<&std::ffi::OsStr>) -> Option<PathBuf> {
    crate::config::user_config_file(home, xdg)
        .and_then(|config| config.parent().map(|dir| dir.join(TABLE_FILE_NAME)))
}

/// The default table file for this process's environment.
#[must_use]
pub fn default_table_file_here() -> Option<PathBuf> {
    default_table_file(
        std::env::var_os("HOME").map(PathBuf::from).as_deref(),
        std::env::var_os("XDG_CONFIG_HOME").as_deref(),
    )
}

/// This run's table location and `[g729] auto_install`, set once at startup.
static CONFIGURED: std::sync::RwLock<Option<(TableLocation, bool)>> = std::sync::RwLock::new(None);

/// Record where this run finds the tables, and whether `[g729] auto_install`
/// allows a download on first need. Called once by the binary at startup; a
/// run that never calls it has no tables, which is what every library caller
/// and unit test sees.
pub fn configure(location: TableLocation, auto_install: bool) {
    if let Ok(mut held) = CONFIGURED.write() {
        *held = Some((location, auto_install));
    }
}

/// The location [`configure`] recorded.
#[must_use]
pub fn configured_location() -> Option<TableLocation> {
    CONFIGURED
        .read()
        .ok()
        .and_then(|held| held.as_ref().map(|(location, _)| location.clone()))
}

/// Whether `[g729] auto_install = true` was configured.
#[must_use]
pub fn auto_install_allowed() -> bool {
    CONFIGURED
        .read()
        .ok()
        .is_some_and(|held| held.as_ref().is_some_and(|(_, auto)| *auto))
}

/// Whether this run decodes G.729: the feature is built in and the tables
/// load.
#[must_use]
pub fn available() -> bool {
    unavailable_reason().is_none()
}

/// Why this run does not decode G.729, or `None` when it does.
#[must_use]
pub fn unavailable_reason() -> Option<String> {
    #[cfg(feature = "g729")]
    {
        tables().err()
    }
    #[cfg(not(feature = "g729"))]
    {
        Some(NOT_BUILT.to_string())
    }
}

/// Read and check the table file at `path`.
///
/// # Errors
///
/// [`NOT_INSTALLED`] when there is no file at `path`; otherwise a message
/// naming the file, why it was refused, and the command that replaces it.
#[cfg(feature = "g729")]
pub fn load(path: &Path) -> Result<g729::Tables, String> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(NOT_INSTALLED.into()),
        Err(e) => {
            return Err(format!(
                "G.729 not decoded: cannot read the table file {}: {e}; run sipnab g729 install",
                path.display()
            ));
        }
    };
    g729::Tables::from_bytes(&bytes).map_err(|e| refusal(path, &e))
}

/// The message for a table file the loader refused. A values-hash refusal
/// names the expected and the actual hash.
#[cfg(feature = "g729")]
fn refusal(path: &Path, e: &g729::TableError) -> String {
    let detail = match e {
        g729::TableError::ValuesHash => {
            let actual = values_hash_of_file(path).unwrap_or_else(|| "unknown".into());
            format!(
                "its values hash is {actual}, expected {}",
                g729::tables::VALUES_SHA256
            )
        }
        other => other.to_string(),
    };
    format!(
        "G.729 not decoded: the table file {} was refused ({detail}); run sipnab g729 install",
        path.display()
    )
}

/// The sha256 of the values a table file holds, by the loader's rule, when
/// its layout is valid. For a refusal message only.
#[cfg(feature = "g729")]
fn values_hash_of_file(path: &Path) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    values_hash(&bytes)
}

/// The sha256 of the values in table-file `bytes` (each value as a
/// little-endian i16, in file order, entry headers excluded), when the layout
/// is valid. The same rule [`g729::Tables::from_bytes`] checks.
#[cfg(feature = "g729")]
#[must_use]
pub fn values_hash(bytes: &[u8]) -> Option<String> {
    use sha2::{Digest, Sha256};
    if bytes.len() != g729::FILE_LEN || bytes.get(..8)? != g729::tables::FILE_MAGIC {
        return None;
    }
    let mut hasher = Sha256::new();
    let mut at = 12;
    for _ in 0..g729::tables::ENTRIES.len() {
        let count = u32::from_le_bytes(bytes.get(at + 2..at + 6)?.try_into().ok()?) as usize;
        at += 6;
        hasher.update(bytes.get(at..at + 2 * count)?);
        at += 2 * count;
    }
    Some(hex(&hasher.finalize()))
}

/// Lowercase hex.
#[cfg(feature = "g729")]
pub(crate) fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut s, b| {
        // Writing to a String cannot fail.
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// The tables loaded once for the process, after the first successful load.
#[cfg(feature = "g729")]
static LOADED: std::sync::OnceLock<&'static g729::Tables> = std::sync::OnceLock::new();

/// This run's tables.
///
/// Loaded from the [`configured_location`] the first time it succeeds and
/// kept for the process: the decoder borrows them for as long as a stream
/// decodes. A failure is not kept, so a `sipnab g729 install` during a run
/// is seen by the next stream.
///
/// # Errors
///
/// [`NOT_INSTALLED`] when no file is configured or present, or the loader's
/// refusal.
#[cfg(feature = "g729")]
pub fn tables() -> Result<&'static g729::Tables, String> {
    #[cfg(test)]
    if let Some(chosen) = test_support::chosen() {
        return chosen.ok_or_else(|| NOT_INSTALLED.to_string());
    }
    if let Some(tables) = LOADED.get() {
        return Ok(tables);
    }
    let location = configured_location().unwrap_or_default();
    let path = location.path().ok_or_else(|| NOT_INSTALLED.to_string())?;
    let tables = load(path)?;
    Ok(LOADED.get_or_init(|| Box::leak(Box::new(tables))))
}

/// Tables for unit tests: imported through the real install path from the
/// ITU-T package `scripts/fetch-g729-vectors.py` fetches, and chosen per test
/// thread so one test's tables cannot leak into another's.
#[cfg(all(test, feature = "g729"))]
pub(crate) mod test_support {
    use std::cell::Cell;

    thread_local! {
        /// `Some(Some(t))`: this thread decodes with `t`. `Some(None)`: this
        /// thread has no tables. `None`: the process-wide answer.
        static CHOSEN: Cell<Option<Option<&'static g729::Tables>>> = const { Cell::new(None) };
    }

    /// The tables chosen for this thread, if any choice was made.
    pub(crate) fn chosen() -> Option<Option<&'static g729::Tables>> {
        CHOSEN.with(Cell::get)
    }

    /// Decode with the imported tables on this thread.
    ///
    /// # Errors
    ///
    /// The fetched package is missing: the message names the fetch command.
    pub(crate) fn use_tables() -> Result<&'static g729::Tables, String> {
        let tables = imported()?;
        CHOSEN.with(|c| c.set(Some(Some(tables))));
        Ok(tables)
    }

    /// Decode with no tables on this thread, whatever the process holds.
    pub(crate) fn use_no_tables() {
        CHOSEN.with(|c| c.set(Some(None)));
    }

    /// The fetched package's extracted source directory,
    /// `crates/g729/test-vectors/itu-source`.
    pub(crate) fn package_dir() -> Result<std::path::PathBuf, String> {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("crates/g729/test-vectors/itu-source");
        if dir.is_dir() {
            Ok(dir)
        } else {
            Err(format!(
                "the ITU-T G.729 package is not fetched ({} is missing): run \
                 `python3 scripts/fetch-g729-vectors.py` from the repository root",
                dir.display()
            ))
        }
    }

    /// The table file built by `g729::import_from_itu`, once per test binary.
    pub(crate) fn table_file() -> Result<&'static [u8], String> {
        static FILE: std::sync::OnceLock<Result<Vec<u8>, String>> = std::sync::OnceLock::new();
        FILE.get_or_init(|| {
            g729::import_from_itu(&package_dir()?).map_err(|e| {
                format!("import_from_itu failed: {e}; run `python3 scripts/fetch-g729-vectors.py`")
            })
        })
        .as_deref()
        .map_err(Clone::clone)
    }

    /// The tables loaded from [`table_file`], once per test binary.
    fn imported() -> Result<&'static g729::Tables, String> {
        static TABLES: std::sync::OnceLock<Result<&'static g729::Tables, String>> =
            std::sync::OnceLock::new();
        TABLES
            .get_or_init(|| {
                g729::Tables::from_bytes(table_file()?)
                    .map(|t| &*Box::leak(Box::new(t)))
                    .map_err(|e| format!("the imported table file: {e}"))
            })
            .clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "g729")]
    type TestError = Box<dyn std::error::Error>;

    fn loc(flag: Option<&str>, key: Option<&str>, default: Option<&str>) -> TableLocation {
        TableLocation {
            flag: flag.map(PathBuf::from),
            key: key.map(PathBuf::from),
            default: default.map(PathBuf::from),
        }
    }

    /// The flag wins over the key, the key over the default, and with none
    /// there is no file to read.
    #[test]
    fn the_flag_then_the_key_then_the_default() {
        let all = loc(Some("/f"), Some("/k"), Some("/d"));
        assert_eq!(all.path(), Some(Path::new("/f")));
        assert_eq!(
            loc(None, Some("/k"), Some("/d")).path(),
            Some(Path::new("/k"))
        );
        assert_eq!(loc(None, None, Some("/d")).path(), Some(Path::new("/d")));
        assert_eq!(loc(None, None, None).path(), None);
    }

    /// The default file sits beside the user's config file, by the same
    /// `$XDG_CONFIG_HOME` rule.
    #[test]
    fn the_default_file_is_beside_the_user_config_file() {
        let home = Path::new("/home/u");
        assert_eq!(
            default_table_file(Some(home), None),
            Some(PathBuf::from("/home/u/.config/sipnab/g729-tables.bin"))
        );
        assert_eq!(
            default_table_file(Some(home), Some(std::ffi::OsStr::new("/x"))),
            Some(PathBuf::from("/x/sipnab/g729-tables.bin"))
        );
        assert_eq!(
            default_table_file(Some(home), Some(std::ffi::OsStr::new("rel"))),
            Some(PathBuf::from("/home/u/.config/sipnab/g729-tables.bin")),
            "a relative XDG_CONFIG_HOME is ignored, as for the config file"
        );
        assert_eq!(default_table_file(None, None), None);
    }

    /// The message a stream without tables carries names the reason and the
    /// command, word for word.
    #[test]
    fn the_not_installed_message_names_the_command() {
        assert_eq!(
            NOT_INSTALLED,
            "G.729 not decoded: codebook tables not installed; run sipnab g729 install"
        );
    }

    /// A missing file is "not installed"; a file that is not the tables is
    /// refused with the path and the command.
    #[cfg(feature = "g729")]
    #[test]
    fn a_missing_or_wrong_file_is_refused_with_the_command() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let missing = dir.path().join("absent.bin");
        assert_eq!(load(&missing).err().as_deref(), Some(NOT_INSTALLED));
        let wrong = dir.path().join("wrong.bin");
        std::fs::write(&wrong, b"not a table file")?;
        let msg = load(&wrong).err().ok_or("a wrong file is refused")?;
        assert!(msg.contains(&wrong.display().to_string()), "{msg}");
        assert!(msg.ends_with("run sipnab g729 install"), "{msg}");
        Ok(())
    }

    /// A table file of the right layout whose values differ is refused naming
    /// the expected and the actual values hash.
    #[cfg(feature = "g729")]
    #[test]
    fn a_values_hash_refusal_names_both_hashes() -> Result<(), TestError> {
        let mut bytes = test_support::table_file()?.to_vec();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        let actual = values_hash(&bytes).ok_or("the layout is valid")?;
        assert_ne!(actual, g729::tables::VALUES_SHA256);
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("altered.bin");
        std::fs::write(&path, &bytes)?;
        let msg = load(&path).err().ok_or("altered values are refused")?;
        assert!(msg.contains(&actual), "{msg}");
        assert!(msg.contains(g729::tables::VALUES_SHA256), "{msg}");
        Ok(())
    }

    /// The real tables load, and their values hash is the pinned one.
    #[cfg(feature = "g729")]
    #[test]
    fn the_imported_tables_load_and_hash_to_the_pin() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join(TABLE_FILE_NAME);
        std::fs::write(&path, test_support::table_file()?)?;
        let tables = load(&path)?;
        assert_eq!(tables.values_sha256_hex(), g729::tables::VALUES_SHA256);
        assert_eq!(
            values_hash(test_support::table_file()?).as_deref(),
            Some(g729::tables::VALUES_SHA256)
        );
        Ok(())
    }
}
