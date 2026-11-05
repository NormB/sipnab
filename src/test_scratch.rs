// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! A scratch directory owned by a guard, for tests.
//!
//! The lib's unit tests reach it as `crate::test_scratch`; integration tests
//! mount this same file with `#[path = "../src/test_scratch.rs"]`, so both
//! sides use one definition.
//!
//! A test that names its directory under the system temp directory and removes
//! it on its own last line leaves it behind whenever it fails. On 2026-10-27
//! the temp directory of the machine that runs these tests held 23,710
//! `sipnab*` directories left that way. [`ScratchDir`] removes its directory
//! when it drops, which a panicking test does too, and its random name never
//! collides with another process. `tests/temp_path_isolation_test.rs` refuses
//! the pattern it replaces.
#![allow(dead_code)]

use std::path::{Path, PathBuf};

/// A fresh directory under the system temp directory, named `<prefix>` and a
/// random suffix, removed when this value drops: on a failing test as well as
/// on a passing one.
///
/// It dereferences to its [`PathBuf`], so it stands in wherever a test used
/// the path it built by hand.
#[derive(Debug)]
pub struct ScratchDir {
    path: PathBuf,
    guard: tempfile::TempDir,
}

impl ScratchDir {
    /// Create the directory. `prefix` names it for whoever lists the temp
    /// directory; it ends in `-` by convention.
    ///
    /// # Errors
    /// When the directory cannot be created.
    pub fn new(prefix: &str) -> std::io::Result<Self> {
        let guard = tempfile::Builder::new().prefix(prefix).tempdir()?;
        Ok(Self {
            path: guard.path().to_path_buf(),
            guard,
        })
    }

    /// As [`Self::new`], under `parent` instead of the system temp directory:
    /// for a test whose directory has to live beside its build, under
    /// `CARGO_TARGET_TMPDIR`.
    ///
    /// # Errors
    /// When the directory cannot be created.
    pub fn new_in(parent: &Path, prefix: &str) -> std::io::Result<Self> {
        std::fs::create_dir_all(parent)?;
        let guard = tempfile::Builder::new().prefix(prefix).tempdir_in(parent)?;
        Ok(Self {
            path: guard.path().to_path_buf(),
            guard,
        })
    }

    /// The directory.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl std::ops::Deref for ScratchDir {
    type Target = PathBuf;

    fn deref(&self) -> &PathBuf {
        &self.path
    }
}

impl AsRef<std::ffi::OsStr> for ScratchDir {
    fn as_ref(&self) -> &std::ffi::OsStr {
        self.path.as_os_str()
    }
}

impl AsRef<Path> for ScratchDir {
    fn as_ref(&self) -> &Path {
        &self.path
    }
}
