// SPDX-License-Identifier: MIT OR Apache-2.0

//! Refuse to write where we are reading.
//!
//! `sipnab -I capture.pcap -O capture.pcap` opened the capture, truncated the
//! same file as the output, wrote back whatever it had already read, and exited
//! 0. The original is gone. One tab-completion reaches it, and an incident
//! capture is very often the only copy that will ever exist.
//!
//! There is no correct interpretation of that command. Nobody means "replace my
//! evidence with a partial re-encoding of itself", and no output is worth the
//! input it destroys. So this is a **precondition**: the collision is decided
//! before anything is opened, not reported after the writer has already
//! truncated the file. A guard that fires after the open still loses the data.
//!
//! # Identity is canonical, not textual
//!
//! `a.pcap`, `./a.pcap`, `dir/../a.pcap` and a symlink pointing at any of them
//! are one file, and the shell hands out all four spellings freely — the
//! symlink case in particular is how a `latest.pcap` convenience link eats the
//! capture it points at. Comparison is therefore between canonical paths. The
//! output usually does not exist yet, so its parent directory is canonicalized
//! and the file name appended; that resolves every symlink and `..` on the way
//! down to the directory, which is where the aliasing lives.
//!
//! # The whole input SET, not the first `-I`
//!
//! `-I` takes a file, a directory, or a glob, and repeats. Writing into a
//! directory that is being read is the same failure with more files in it, and
//! it is worse on the second run than the first: run one merely creates the
//! output, run two reads it back as an input and the operator has silently
//! doubled their traffic — or, when the name collides, lost a capture. Both the
//! resolved set and the directories named by `-I` are protected.
//!
//! # Rotation counts as output
//!
//! `--split` turns `-O out.pcap` into `out_00001.pcap`, `out_00002.pcap`, …
//! Those are output paths too, so an input that already carries a rotated name
//! for the same base is refused with the rest.

use std::path::{Path, PathBuf};

/// Resolve a path to a stable identity, whether or not it exists yet.
///
/// An existing path canonicalizes directly (resolving symlinks). One that does
/// not exist — the usual case for an output — has its parent canonicalized and
/// its file name appended, which resolves the aliasing that matters (symlinked
/// or `..`-relative directories) without requiring the file itself. If even the
/// parent cannot be resolved, the path is made absolute against the current
/// directory so two spellings still compare equal more often than not.
pub fn canonical_target(path: &Path) -> PathBuf {
    if let Ok(c) = path.canonicalize() {
        return c;
    }
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        // A bare "out.pcap" is relative to the current directory.
        _ => PathBuf::from("."),
    };
    match (parent.canonicalize(), path.file_name()) {
        (Ok(dir), Some(name)) => dir.join(name),
        _ => std::env::current_dir()
            .map(|d| d.join(path))
            .unwrap_or_else(|_| path.to_path_buf()),
    }
}

/// The set of paths a run must not write to: every capture file it will read,
/// every directory it was told to read, and every glob it will expand.
#[derive(Debug, Clone, Default)]
pub struct ProtectedInputs {
    /// Canonical paths of the capture files this run reads.
    files: Vec<PathBuf>,
    /// Canonical directories named by `-I`, each paired with whether the walk
    /// descends into subdirectories.
    dirs: Vec<(PathBuf, bool)>,
    /// `-I` glob patterns, rooted at a canonical directory where possible.
    ///
    /// A glob names no file until it is expanded, so a caller that has not
    /// resolved the set (the MCP server, which must not re-open every capture
    /// to answer one export) would otherwise have nothing to compare against.
    globs: Vec<String>,
}

impl ProtectedInputs {
    /// Build the protected set from the `-I` specs and, when it is known, the
    /// resolved capture files.
    ///
    /// # Arguments
    ///
    /// * `specs` — the raw `-I` arguments. Used on their own terms, not merely
    ///   as a route to the resolved set: a spec naming a file protects that
    ///   file, a spec naming a directory protects writing inside it (the
    ///   directory is never itself a member of the resolved set), and a glob
    ///   protects everything it would match.
    /// * `resolved` — the capture files `input_set::resolve` produced. May be
    ///   empty when the caller has not resolved them; the spec-level rules
    ///   still apply.
    /// * `recursive` — whether `--recursive` was given, which decides whether a
    ///   subdirectory of an `-I` directory is also being read.
    pub fn new(specs: &[String], resolved: &[PathBuf], recursive: bool) -> Self {
        let mut files: Vec<PathBuf> = resolved.iter().map(|p| canonical_target(p)).collect();
        let mut dirs: Vec<(PathBuf, bool)> = Vec::new();
        let mut globs: Vec<String> = Vec::new();

        for spec in specs {
            let path = PathBuf::from(spec);
            if path.is_dir() {
                if let Ok(c) = path.canonicalize() {
                    dirs.push((c, recursive));
                }
            } else if path.is_file() {
                let c = canonical_target(&path);
                if !files.contains(&c) {
                    files.push(c);
                }
            } else {
                // Neither yet — a glob, or a path that does not exist (which
                // `resolve` will reject anyway). Keep the pattern.
                globs.push(rooted_glob(spec));
            }
        }

        Self { files, dirs, globs }
    }

    /// True when nothing is protected (no `-I` at all — a live capture).
    pub fn is_empty(&self) -> bool {
        self.files.is_empty() && self.dirs.is_empty() && self.globs.is_empty()
    }

    /// Protect one more capture file, for inputs that arrive after startup.
    ///
    /// The TUI opens captures interactively, so the file it is reading is not
    /// always one the command line named. A file opened in the session is as
    /// much an input as `-I` was, and the save dialog can name it.
    pub fn protect_file(&mut self, path: &Path) {
        let c = canonical_target(path);
        if !self.files.contains(&c) {
            self.files.push(c);
        }
    }

    /// Refuse `output` when it names, or would rotate onto, an input.
    ///
    /// # Arguments
    ///
    /// * `output` — the path the run intends to write.
    /// * `flag` — the flag that named it (`-O`, `--strip-secrets`, …), so the
    ///   message tells the operator which argument to change.
    /// * `split` — whether `--split` is active, which adds the rotated
    ///   `name_00001.ext` family to the paths this run may write.
    ///
    /// # Errors
    ///
    /// A human-readable message naming both paths and the reason.
    pub fn check(&self, output: &Path, flag: &str, split: bool) -> Result<(), String> {
        let target = canonical_target(output);

        for input in &self.files {
            if *input == target {
                return Err(format!(
                    "{flag} '{}' would overwrite the capture being read \
                     ('{}'). They are the same file. Writing it would destroy \
                     the input — choose a different output path.",
                    output.display(),
                    input.display(),
                ));
            }
            if split && is_rotation_of(input, &target) {
                return Err(format!(
                    "{flag} '{}' with --split rotates onto '{}' and so would \
                     overwrite a capture being read. Writing it would destroy \
                     the input — choose a different output path or directory.",
                    output.display(),
                    input.display(),
                ));
            }
        }

        for (dir, recursive) in &self.dirs {
            let inside = if *recursive {
                target.starts_with(dir)
            } else {
                target.parent() == Some(dir.as_path())
            };
            if inside {
                return Err(format!(
                    "{flag} '{}' would overwrite part of the capture set being \
                     read: it writes inside '{}', a directory this run reads. \
                     Even a name that is free today becomes an input on the \
                     next run — write outside the directory instead.",
                    output.display(),
                    dir.display(),
                ));
            }
        }

        for pattern in &self.globs {
            let Ok(pat) = glob::Pattern::new(pattern) else {
                continue;
            };
            if pat.matches_path(&target) || pat.matches_path(output) {
                return Err(format!(
                    "{flag} '{}' would overwrite part of the capture set being \
                     read: it matches the input pattern '{pattern}'. Write \
                     somewhere the pattern does not reach.",
                    output.display(),
                ));
            }
        }

        Ok(())
    }
}

/// Re-root a glob spec on its canonical directory when that directory exists,
/// so a pattern written relatively (`caps/*.pcap`) still matches the absolute,
/// canonical path an output resolves to.
///
/// Returns the spec unchanged when the directory part is itself a pattern or
/// cannot be resolved — matching then falls back to the raw spelling, which is
/// still better than no protection.
fn rooted_glob(spec: &str) -> String {
    let p = Path::new(spec);
    let parent = match p.parent() {
        Some(x) if !x.as_os_str().is_empty() => x.to_path_buf(),
        _ => PathBuf::from("."),
    };
    match (parent.canonicalize(), p.file_name()) {
        (Ok(dir), Some(name)) => dir.join(name).to_string_lossy().into_owned(),
        _ => spec.to_string(),
    }
}

/// True when `candidate` is a `--split` rotation of `base`, i.e. the same
/// directory and extension with a `_NNNNN` sequence appended to the stem.
///
/// Mirrors `writer::rotated_path`, which builds `{stem}_{sequence:05}.{ext}`.
/// Comparing the shape rather than enumerating sequence numbers keeps this
/// correct for a rotation count nobody can know in advance.
fn is_rotation_of(candidate: &Path, base: &Path) -> bool {
    if candidate.parent() != base.parent() {
        return false;
    }
    let base_stem = match base.file_stem().and_then(|s| s.to_str()) {
        Some(s) => s,
        None => return false,
    };
    let base_ext = base.extension().and_then(|s| s.to_str()).unwrap_or("pcap");
    if candidate.extension().and_then(|s| s.to_str()) != Some(base_ext) {
        return false;
    }
    let Some(stem) = candidate.file_stem().and_then(|s| s.to_str()) else {
        return false;
    };
    let Some(seq) = stem
        .strip_prefix(base_stem)
        .and_then(|r| r.strip_prefix('_'))
    else {
        return false;
    };
    !seq.is_empty() && seq.chars().all(|c| c.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A temp directory holding two capture-shaped files.
    fn fixture(name: &str) -> PathBuf {
        let d =
            std::env::temp_dir().join(format!("sipnab-output-guard-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).expect("create temp dir");
        std::fs::write(d.join("a.pcap"), b"not really a pcap").expect("write a");
        std::fs::write(d.join("b.pcap"), b"not really a pcap").expect("write b");
        d
    }

    /// The same file under different spellings is one file.
    #[test]
    fn canonical_target_collapses_spellings() {
        let d = fixture("spellings");
        let plain = d.join("a.pcap");
        let dotted = d.join(".").join("a.pcap");
        let dotdot = d.join("sub").join("..").join("a.pcap");
        std::fs::create_dir_all(d.join("sub")).expect("mkdir sub");
        assert_eq!(canonical_target(&plain), canonical_target(&dotted));
        assert_eq!(canonical_target(&plain), canonical_target(&dotdot));
    }

    /// A not-yet-existing output still resolves through its parent, so a
    /// symlinked directory does not hide a collision.
    #[test]
    fn canonical_target_resolves_a_missing_file_through_its_parent() {
        let d = fixture("missing");
        let missing = d.join("does-not-exist.pcap");
        let resolved = canonical_target(&missing);
        assert!(resolved.is_absolute(), "got {}", resolved.display());
        assert_eq!(resolved.file_name(), missing.file_name());
        assert_eq!(
            resolved.parent(),
            Some(d.canonicalize().expect("canon").as_path())
        );
    }

    /// An output equal to a resolved input is refused; a different one is not.
    #[test]
    fn exact_input_match_is_refused() {
        let d = fixture("exact");
        let a = d.join("a.pcap");
        let p = ProtectedInputs::new(&[], std::slice::from_ref(&a), false);
        let err = p.check(&a, "-O", false).expect_err("must refuse");
        assert!(err.contains("would overwrite"), "got: {err}");
        assert!(p.check(&d.join("out.pcap"), "-O", false).is_ok());
    }

    /// Protection follows the file, not the spelling used to name it.
    #[test]
    fn a_different_spelling_of_an_input_is_refused() {
        let d = fixture("alias");
        let a = d.join("a.pcap");
        let p = ProtectedInputs::new(&[], std::slice::from_ref(&a), false);
        let aliased = d.join(".").join("a.pcap");
        assert!(p.check(&aliased, "-O", false).is_err());
    }

    /// Writing inside a directory being read is refused; a sibling directory
    /// is fine, and a subdirectory only counts when the walk recurses.
    #[test]
    fn writing_inside_an_input_directory_is_refused() {
        let d = fixture("dir");
        std::fs::create_dir_all(d.join("sub")).expect("mkdir sub");
        let specs = vec![d.to_string_lossy().into_owned()];

        let flat = ProtectedInputs::new(&specs, &[], false);
        assert!(flat.check(&d.join("out.pcap"), "-O", false).is_err());
        assert!(
            flat.check(&d.join("sub").join("out.pcap"), "-O", false)
                .is_ok(),
            "without --recursive a subdirectory is not being read"
        );

        let deep = ProtectedInputs::new(&specs, &[], true);
        assert!(
            deep.check(&d.join("sub").join("out.pcap"), "-O", true)
                .is_err(),
            "--recursive reads subdirectories, so writing there collides"
        );
    }

    /// With `--split`, a rotated name that is already an input is refused;
    /// without `--split` the same pair is fine.
    #[test]
    fn split_rotation_onto_an_input_is_refused() {
        let d = fixture("split");
        let rotated = d.join("cap_00001.pcap");
        std::fs::write(&rotated, b"x").expect("write rotated");
        let base = d.join("cap.pcap");
        let p = ProtectedInputs::new(&[], &[rotated], false);
        assert!(p.check(&base, "-O", true).is_err(), "rotation collides");
        assert!(
            p.check(&base, "-O", false).is_ok(),
            "without --split nothing rotates onto it"
        );
    }

    /// The rotation shape test accepts only `{stem}_{digits}.{ext}` siblings.
    #[test]
    fn rotation_shape_is_precise() {
        let base = Path::new("/caps/out.pcap");
        assert!(is_rotation_of(Path::new("/caps/out_00001.pcap"), base));
        assert!(is_rotation_of(Path::new("/caps/out_7.pcap"), base));
        // Wrong directory, wrong extension, no separator, non-numeric suffix.
        assert!(!is_rotation_of(Path::new("/other/out_00001.pcap"), base));
        assert!(!is_rotation_of(Path::new("/caps/out_00001.pcapng"), base));
        assert!(!is_rotation_of(Path::new("/caps/out00001.pcap"), base));
        assert!(!is_rotation_of(Path::new("/caps/out_final.pcap"), base));
        assert!(!is_rotation_of(Path::new("/caps/other_00001.pcap"), base));
    }

    /// A live capture protects nothing, so every output is allowed.
    #[test]
    fn no_inputs_means_no_restriction() {
        let p = ProtectedInputs::new(&[], &[], false);
        assert!(p.is_empty());
        assert!(p.check(Path::new("/tmp/anything.pcap"), "-O", true).is_ok());
    }

    /// A spec that names a file protects that file even when the caller never
    /// resolved the set — the MCP server's case.
    #[test]
    fn a_named_file_spec_is_protected_without_resolution() {
        let d = fixture("spec-only");
        let a = d.join("a.pcap");
        let specs = vec![a.to_string_lossy().into_owned()];
        let p = ProtectedInputs::new(&specs, &[], false);
        assert!(p.check(&a, "filename", false).is_err());
        assert!(
            p.check(&d.join("elsewhere.pcap"), "filename", false)
                .is_ok()
        );
    }

    /// A glob spec protects everything it would expand to, including files
    /// that do not exist yet.
    #[test]
    fn a_glob_spec_protects_what_it_would_match() {
        let d = fixture("glob");
        let spec = d.join("*.pcap").to_string_lossy().into_owned();
        let p = ProtectedInputs::new(&[spec], &[], false);
        assert!(
            p.check(&d.join("a.pcap"), "-O", false).is_err(),
            "an existing match is protected"
        );
        assert!(
            p.check(&d.join("brand-new.pcap"), "-O", false).is_err(),
            "a file the glob would pick up on the next run is protected too"
        );
        assert!(
            p.check(&d.join("notes.txt"), "-O", false).is_ok(),
            "a name the pattern cannot match is fine"
        );
    }
}
