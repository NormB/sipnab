// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! Following a frame pointer back to its bytes.
//!
//! [`crate::capture::packet::FrameRef`] names one frame as
//! `<source>#<ordinal>`. This module turns that name back into the bytes, and
//! — the part that matters — refuses when it cannot be sure they are the right
//! bytes.
//!
//! # Why refusing is the whole point
//!
//! A pointer that resolves to the WRONG frame is worse than no pointer. It
//! manufactures confidence: someone follows it, gets a frame, and has no way
//! to tell that the capture was rotated, truncated or recompressed since the
//! run that produced the pointer. That is the same failure the pcapng writer
//! had when it named the first input file as the source of every frame — the
//! file opened, the count was right, and nothing looked wrong.
//!
//! So [`resolve`] has four outcomes and never guesses between them:
//!
//! | Situation | Outcome |
//! |---|---|
//! | Frame present, digest matches | [`Resolution::Verified`] |
//! | Frame present, pointer carried no digest | [`Resolution::Unverified`] |
//! | Frame present, digest differs | [`ResolveError::Changed`] |
//! | Frame absent, or source unreadable | [`ResolveError::NoSuchFrame`] / [`ResolveError::Unreadable`] |
//!
//! `Unverified` is a distinct answer rather than a convenient synonym for
//! `Verified`, because "here are the bytes, and nobody checked them" is a
//! different statement from "here are the bytes, and they are the ones the
//! finding was about". A caller that treats them alike has thrown away the
//! only thing separating evidence from assertion.

use std::path::Path;

use super::packet::{FrameRef, frame_digest};

/// Bytes recovered by following a pointer, and how much is known about them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolution {
    /// The frame was found and its bytes hash to what the pointer recorded.
    Verified(Vec<u8>),
    /// The frame was found, and the pointer carried no digest, so nothing was
    /// checked. Report it as unverified — never as found.
    Unverified(Vec<u8>),
}

impl Resolution {
    /// The recovered bytes, whichever outcome produced them.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        match self {
            Self::Verified(b) | Self::Unverified(b) => b,
        }
    }

    /// Whether the bytes were checked against the pointer's own digest.
    #[must_use]
    pub fn is_verified(&self) -> bool {
        matches!(self, Self::Verified(_))
    }
}

/// Why a pointer could not be followed to bytes anyone should trust.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolveError {
    /// The text was not a `<source>#<ordinal>` pointer.
    Malformed(String),
    /// The source could not be opened.
    Unreadable {
        /// The source the pointer named.
        source: String,
        /// What went wrong opening it.
        cause: String,
    },
    /// The source holds fewer frames than the ordinal names.
    NoSuchFrame {
        /// The source the pointer named.
        source: String,
        /// The ordinal asked for.
        ordinal: u64,
        /// How many frames the source actually holds.
        frames_present: u64,
    },
    /// The pointer names plaintext lifted out of a process, which never was a
    /// frame on any wire, so there is nothing to seek to — and saying "file not
    /// found" here would be a wrong answer about evidence rather than a missing
    /// one.
    NeverOnTheWire {
        /// The process's command name.
        comm: String,
        /// The process the bytes were read from.
        pid: u32,
        /// Which read from that process this pointer names.
        ordinal: u64,
    },
    /// The frame is there, and it is not the frame the pointer was made
    /// against.
    Changed {
        /// The source the pointer named.
        source: String,
        /// The ordinal asked for.
        ordinal: u64,
    },
}

impl std::fmt::Display for ResolveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(s) => write!(
                f,
                "'{s}' is not a frame pointer; the form is <source>#<ordinal>, \
                 as in capture.pcap#4212"
            ),
            Self::Unreadable { source, cause } => {
                write!(f, "cannot open '{source}': {cause}")
            }
            Self::NoSuchFrame {
                source,
                ordinal,
                frames_present,
            } => write!(
                f,
                "'{source}' holds {frames_present} frame(s), so there is no \
                 frame {ordinal}. The capture may have been truncated since \
                 the pointer was made"
            ),
            Self::NeverOnTheWire { comm, pid, ordinal } => write!(
                f,
                "read {ordinal} came from the TLS library inside {comm} \
                 (pid {pid}); it was never a frame on any wire, so there is no \
                 capture to seek into and no bytes to verify it against. This \
                 is not a missing file"
            ),
            Self::Changed { source, ordinal } => write!(
                f,
                "frame {ordinal} of '{source}' is not the frame this pointer \
                 was made against — the capture changed. Refusing to return \
                 bytes that would be read as evidence for something they are \
                 not"
            ),
        }
    }
}

impl std::error::Error for ResolveError {}

/// Parse `<source>#<ordinal>` into a pointer with no digest.
///
/// Splits on the LAST `#`, because a capture path may legitimately contain
/// one and the ordinal never does. A pointer parsed from text carries no
/// digest — the text form does not encode one — so following it can only ever
/// produce [`Resolution::Unverified`]. That is correct and deliberate: a
/// human typing a pointer at a shell has nothing to verify against.
///
/// # Errors
///
/// Returns [`ResolveError::Malformed`] when there is no `#`, when the source
/// is empty, or when what follows the `#` is not a non-negative integer.
pub fn parse_pointer(text: &str) -> Result<FrameRef, ResolveError> {
    let malformed = || ResolveError::Malformed(text.to_string());
    let (source, tail) = text.rsplit_once('#').ok_or_else(malformed)?;
    if source.is_empty() {
        return Err(malformed());
    }
    // Split on the LAST `#` above, so a path containing `#` keeps it; the tail
    // is ours, and an optional `@<digest>` lives there rather than in the
    // source, where a path could legitimately contain `@`.
    // The optional byte range comes off first, because it sits last. A range
    // that cannot be read REFUSES the whole pointer rather than dropping to
    // the whole frame: dropping it would answer a different question than the
    // one asked, and answer it confidently, which is the one outcome this
    // mechanism exists to prevent.
    let (tail, bytes) = match tail.split_once('+') {
        Some((head, range)) => {
            let (start, end) = range.split_once('-').ok_or_else(malformed)?;
            let start: u32 = start.parse().map_err(|_| malformed())?;
            let end: u32 = end.parse().map_err(|_| malformed())?;
            if end <= start {
                return Err(malformed());
            }
            (head, Some(start..end))
        }
        None => (tail, None),
    };
    let (ordinal, digest) = match tail.split_once('@') {
        Some((o, d)) => {
            let parsed = u64::from_str_radix(d, 16).map_err(|_| malformed())?;
            (o, Some(parsed))
        }
        None => (tail, None),
    };
    let ordinal: u64 = ordinal.parse().map_err(|_| malformed())?;
    Ok(FrameRef {
        source: std::sync::Arc::from(source),
        bytes,
        origin: super::packet::FrameOrigin {
            ordinal,
            digest,
            // A pointer parsed from text names a source someone intends to
            // resolve; `resolve` refuses a uprobe pointer separately, on the
            // ground that those bytes were never on a wire.
            verifiable: true,
        },
        kind: super::packet::FrameSource::from_source_name(source),
    })
}

/// [`resolve`], plus the libpcap link type of the capture the frame is in.
///
/// # Errors
///
/// As [`resolve`].
pub fn resolve_with_link_type(pointer: &FrameRef) -> Result<(Resolution, i32), ResolveError> {
    resolve_from(pointer, None)
}

/// What a pointer's source was opened as before the process dropped
/// privileges ([`open_source_up_front`]). Nothing has been read from it.
#[derive(Debug)]
pub struct OpenedSource {
    /// The file that was opened: the source itself, or the file above it.
    path: std::path::PathBuf,
    /// The open's result.
    file: std::io::Result<std::fs::File>,
    /// Whether `path` is a file above a source that does not exist, so the
    /// source can only be a member of it.
    above: bool,
}

/// Open the file a pointer's source names, or, when the source does not
/// exist, the regular file above it that it may be a member of. Reads file
/// types and opens one descriptor; no content is read.
#[must_use]
pub fn open_source_up_front(source: &str) -> OpenedSource {
    let path = Path::new(source);
    let (path, above) = match super::archive::first_file_above(source) {
        Some(file) if !path.exists() => (file, true),
        _ => (path.to_path_buf(), false),
    };
    OpenedSource {
        file: super::file::open_up_front(&path),
        path,
        above,
    }
}

/// [`resolve`] through a source opened up front: the capture, or the archive
/// that holds it, is read through its descriptor and never by its path.
///
/// # Errors
///
/// As [`resolve`].
pub fn resolve_opened(
    pointer: &FrameRef,
    opened: OpenedSource,
) -> Result<Resolution, ResolveError> {
    resolve_from(pointer, Some(opened)).map(|(resolution, _)| resolution)
}

/// [`resolve_with_link_type`], by path or through `opened`.
fn resolve_from(
    pointer: &FrameRef,
    opened: Option<OpenedSource>,
) -> Result<(Resolution, i32), ResolveError> {
    // Refuse before touching the filesystem. These bytes were read out of a
    // process and never existed as a frame, so every filesystem answer below
    // would be about the wrong question.
    if let super::packet::FrameSource::Uprobe { comm, pid } = &pointer.kind {
        return Err(ResolveError::NeverOnTheWire {
            comm: comm.to_string(),
            pid: *pid,
            ordinal: pointer.origin.ordinal,
        });
    }
    let (mut cap, _guard) = match opened {
        Some(opened) => open_opened_source(&pointer.source, opened)?,
        None => open_source(&pointer.source)?,
    };
    let link_type = cap.get_datalink().0;

    let mut seen: u64 = 0;
    while let Ok(pkt) = cap.next_packet() {
        if seen == pointer.origin.ordinal {
            let bytes = pkt.data.to_vec();
            let resolution = match pointer.origin.digest {
                // Nothing to check against. Say so rather than implying a
                // check happened.
                None => Resolution::Unverified(bytes),
                Some(want) if frame_digest(&bytes) == want => Resolution::Verified(bytes),
                Some(_) => {
                    return Err(ResolveError::Changed {
                        source: pointer.source.to_string(),
                        ordinal: pointer.origin.ordinal,
                    });
                }
            };
            return Ok((resolution, link_type));
        }
        seen += 1;
    }

    Err(ResolveError::NoSuchFrame {
        source: pointer.source.to_string(),
        ordinal: pointer.origin.ordinal,
        frames_present: seen,
    })
}

/// Whatever [`open_source`] had to write out to open a capture, deleted on
/// drop.
enum SourceGuard {
    /// A file on disk, or a compressed one inflated by `open_offline`.
    File {
        /// Held only to be dropped.
        _inflated: Option<super::file::OfflineGuard>,
    },
    /// A member written out of an archive.
    Member {
        /// Held only to be dropped.
        _dir: super::archive::ExtractDir,
    },
}

/// Open the capture a pointer's source names: a file, or — when the source is
/// `<archive>/<member>` — that member, written out of the archive afresh.
///
/// Written out afresh rather than taken from wherever a run extracted it,
/// because a pointer outlives the run that minted it. The walk is the one the
/// run used, so a label it produced finds the same member here.
fn open_source(source: &str) -> Result<(pcap::Capture<pcap::Offline>, SourceGuard), ResolveError> {
    let unreadable = |cause: String| ResolveError::Unreadable {
        source: source.to_string(),
        cause,
    };
    let path = Path::new(source);
    if !path.exists()
        && let Some(archive) = super::archive::locate_member(source)
    {
        let limits = super::archive::Limits::for_run();
        let extracted = super::archive::extract_member(&archive, source, &limits);
        return open_member(source, &archive, extracted);
    }
    super::file::open_offline(path)
        .map(|(cap, guard)| (cap, SourceGuard::File { _inflated: guard }))
        .map_err(|e| unreadable(format!("{e:#}")))
}

/// Open the member a walk of `archive` for the label `source` wrote out.
fn open_member(
    source: &str,
    archive: &Path,
    extracted: std::io::Result<Option<(super::archive::Member, super::archive::ExtractDir)>>,
) -> Result<(pcap::Capture<pcap::Offline>, SourceGuard), ResolveError> {
    let unreadable = |cause: String| ResolveError::Unreadable {
        source: source.to_string(),
        cause,
    };
    match extracted {
        Ok(Some((member, dir))) => pcap::Capture::from_file(&member.path)
            .map(|cap| (cap, SourceGuard::Member { _dir: dir }))
            .map_err(|e| unreadable(e.to_string())),
        Ok(None) => Err(unreadable(format!(
            "'{}' holds no member named '{}'",
            archive.display(),
            source
                .strip_prefix(&archive.display().to_string())
                .map_or(source, |rest| rest.trim_start_matches('/'))
        ))),
        Err(e) => Err(unreadable(e.to_string())),
    }
}

/// [`open_source`] through what [`open_source_up_front`] opened.
fn open_opened_source(
    source: &str,
    opened: OpenedSource,
) -> Result<(pcap::Capture<pcap::Offline>, SourceGuard), ResolveError> {
    let unreadable = |cause: String| ResolveError::Unreadable {
        source: source.to_string(),
        cause,
    };
    let OpenedSource { path, file, above } = opened;
    let file = file.map_err(|e| unreadable(e.to_string()))?;
    let member = super::file::Member::opened(&path, &file);
    if !above {
        return member
            .open_for_libpcap()
            .map(|(cap, guard)| (cap, SourceGuard::File { _inflated: guard }))
            .map_err(|e| unreadable(format!("{e:#}")));
    }
    // The source does not exist and `path` is the file above it: a member
    // label when that file is an archive, and a path that leads nowhere when
    // it is not, which the open by path reports as it always did.
    if !matches!(member.container_format(), Ok(Some(f)) if super::archive::unwraps(f)) {
        return super::file::open_offline(Path::new(source))
            .map(|(cap, guard)| (cap, SourceGuard::File { _inflated: guard }))
            .map_err(|e| unreadable(format!("{e:#}")));
    }
    let limits = super::archive::Limits::for_run();
    let extracted = super::file::rewound(&file)
        .and_then(|file| super::archive::extract_member_opened(file, &path, source, &limits));
    open_member(source, &path, extracted)
}

/// Follow a pointer back to the frame's bytes.
///
/// # Errors
///
/// Returns [`ResolveError`] rather than bytes whenever the answer would be a
/// guess: the source will not open, it is too short, or the frame there is
/// not the frame the pointer was made against.
pub fn resolve(pointer: &FrameRef) -> Result<Resolution, ResolveError> {
    resolve_with_link_type(pointer).map(|(resolution, _)| resolution)
}

#[cfg(test)]
mod archive_member_tests {
    use super::*;
    use crate::capture::archive::tar::testutil::{Spec, build};
    use crate::capture::packet::{FrameOrigin, FrameRef, FrameSource};
    use std::io::Write;

    /// Any error a test can return; `?` converts into it.
    type TestError = Box<dyn std::error::Error>;

    /// A classic pcap holding one record per frame, each stamped a second on.
    fn pcap_of(link_type: u32, frames: &[&[u8]]) -> Vec<u8> {
        let mut f = Vec::new();
        f.extend_from_slice(&0xa1b2_c3d4u32.to_le_bytes());
        f.extend_from_slice(&2u16.to_le_bytes());
        f.extend_from_slice(&4u16.to_le_bytes());
        for v in [0u32, 0, 65_535, link_type] {
            f.extend_from_slice(&v.to_le_bytes());
        }
        for (i, frame) in frames.iter().enumerate() {
            for v in [1_000 + i as u32, 0, frame.len() as u32, frame.len() as u32] {
                f.extend_from_slice(&v.to_le_bytes());
            }
            f.extend_from_slice(frame);
        }
        f
    }

    fn gzip(data: &[u8]) -> Result<Vec<u8>, TestError> {
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        enc.write_all(data).map_err(|e| format!("gzip: {e:?}"))?;
        Ok(enc.finish().map_err(|e| format!("gzip: {e:?}"))?)
    }

    fn pointer(source: &str, ordinal: u64) -> FrameRef {
        FrameRef {
            source: std::sync::Arc::from(source),
            origin: FrameOrigin {
                ordinal,
                digest: None,
                verifiable: true,
            },
            kind: FrameSource::Wire,
            bytes: None,
        }
    }

    // ---- a source opened up front, read through its descriptor ----
    //
    // Each success test removes the file after it is opened: a resolver
    // that opened it by path again would find nothing.

    /// Write `bytes` as `name` in a new directory.
    fn written(name: &str, bytes: &[u8]) -> Result<(tempfile::TempDir, String), TestError> {
        let tmp = tempfile::tempdir().map_err(|e| format!("tmp: {e:?}"))?;
        let path = tmp.path().join(name);
        std::fs::write(&path, bytes).map_err(|e| format!("write: {e:?}"))?;
        Ok((tmp, path.display().to_string()))
    }

    /// Open `source` up front, remove `file`, and resolve through the handle.
    fn resolved_after_removal(
        file: &str,
        pointer: &FrameRef,
    ) -> Result<Result<Resolution, ResolveError>, TestError> {
        let opened = open_source_up_front(&pointer.source);
        std::fs::remove_file(file).map_err(|e| format!("remove: {e:?}"))?;
        Ok(resolve_opened(pointer, opened))
    }

    #[test]
    fn an_opened_capture_resolves_with_its_path_gone() -> Result<(), TestError> {
        let (_tmp, path) = written("a.pcap", &pcap_of(1, &[b"zero", b"one"]))?;
        let got =
            resolved_after_removal(&path, &pointer(&path, 1))?.map_err(|e| format!("{e:?}"))?;
        assert_eq!(
            got,
            Resolution::Unverified(b"one".to_vec()),
            "the frame was read through the descriptor"
        );
        Ok(())
    }

    #[test]
    fn an_opened_gzip_capture_resolves_with_its_path_gone() -> Result<(), TestError> {
        let (_tmp, path) = written("a.pcap.gz", &gzip(&pcap_of(1, &[b"zero", b"one"]))?)?;
        let got =
            resolved_after_removal(&path, &pointer(&path, 0))?.map_err(|e| format!("{e:?}"))?;
        assert_eq!(got.bytes(), b"zero", "inflated from the descriptor");
        Ok(())
    }

    #[test]
    fn an_opened_archive_gives_its_member_with_its_path_gone() -> Result<(), TestError> {
        let inner = build(&[Spec::file(
            "b.pcap.gz",
            &gzip(&pcap_of(1, &[b"b0", b"b1"]))?,
        )]);
        let outer = build(&[
            Spec::file("dir/a.pcap", &pcap_of(1, &[b"a0", b"a1"])),
            Spec::file("in.tar", &inner),
        ]);
        let (_tmp, path) = written("set.tgz", &gzip(&outer)?)?;
        let got = resolved_after_removal(&path, &pointer(&format!("{path}/dir/a.pcap"), 1))?
            .map_err(|e| format!("{e:?}"))?;
        assert_eq!(
            got.bytes(),
            b"a1",
            "the member was walked out of the descriptor"
        );
        Ok(())
    }

    #[test]
    fn an_opened_archive_gives_a_nested_member() -> Result<(), TestError> {
        let inner = build(&[Spec::file(
            "b.pcap.gz",
            &gzip(&pcap_of(1, &[b"b0", b"b1"]))?,
        )]);
        let outer = build(&[Spec::file("in.tar", &inner)]);
        let (_tmp, path) = written("set.tar", &outer)?;
        let got = resolved_after_removal(&path, &pointer(&format!("{path}/in.tar/b.pcap.gz"), 1))?
            .map_err(|e| format!("{e:?}"))?;
        assert_eq!(
            got.bytes(),
            b"b1",
            "through the nested archive and the gzip"
        );
        Ok(())
    }

    #[test]
    fn an_opened_source_verifies_a_digest() -> Result<(), TestError> {
        let (_tmp, path) = written("a.pcap", &pcap_of(1, &[b"zero"]))?;
        let mut wanted = pointer(&path, 0);
        wanted.origin.digest = Some(frame_digest(b"zero"));
        let got = resolved_after_removal(&path, &wanted)?.map_err(|e| format!("{e:?}"))?;
        assert_eq!(
            got,
            Resolution::Verified(b"zero".to_vec()),
            "the digest was checked"
        );
        Ok(())
    }

    #[test]
    fn an_opened_source_resolves_as_the_path_does() -> Result<(), TestError> {
        let (_tmp, path) = written("a.pcap", &pcap_of(1, &[b"zero", b"one"]))?;
        let by_path = resolve(&pointer(&path, 1)).map_err(|e| format!("{e:?}"))?;
        let opened = resolve_opened(&pointer(&path, 1), open_source_up_front(&path))
            .map_err(|e| format!("{e:?}"))?;
        assert_eq!(by_path, opened, "one answer, two ways to reach the file");
        Ok(())
    }

    #[test]
    fn an_opened_source_with_a_changed_frame_is_refused() -> Result<(), TestError> {
        let (_tmp, path) = written("a.pcap", &pcap_of(1, &[b"zero"]))?;
        let mut wanted = pointer(&path, 0);
        wanted.origin.digest = Some(frame_digest(b"other"));
        let refused = resolved_after_removal(&path, &wanted)?;
        assert!(
            matches!(refused, Err(ResolveError::Changed { ordinal: 0, .. })),
            "a digest that does not match is refused: {refused:?}"
        );
        Ok(())
    }

    #[test]
    fn an_opened_source_too_short_for_the_ordinal_is_refused() -> Result<(), TestError> {
        let (_tmp, path) = written("a.pcap", &pcap_of(1, &[b"zero"]))?;
        let refused = resolved_after_removal(&path, &pointer(&path, 5))?;
        assert!(
            matches!(
                refused,
                Err(ResolveError::NoSuchFrame {
                    frames_present: 1,
                    ..
                })
            ),
            "the count of frames present comes back: {refused:?}"
        );
        Ok(())
    }

    #[test]
    fn a_source_that_does_not_exist_is_unreadable_when_opened_up_front() {
        let source = "/nonexistent-sipnab-test/a.pcap";
        let refused = resolve_opened(&pointer(source, 0), open_source_up_front(source));
        assert!(
            matches!(refused, Err(ResolveError::Unreadable { .. })),
            "nothing to open: {refused:?}"
        );
    }

    #[test]
    fn an_opened_file_that_is_no_capture_is_unreadable() -> Result<(), TestError> {
        let (_tmp, path) = written("a.pcap", b"not a capture at all")?;
        let refused = resolved_after_removal(&path, &pointer(&path, 0))?;
        assert!(
            matches!(refused, Err(ResolveError::Unreadable { .. })),
            "libpcap refuses the descriptor's bytes: {refused:?}"
        );
        Ok(())
    }

    #[test]
    fn an_opened_archive_without_the_member_says_so() -> Result<(), TestError> {
        let outer = build(&[Spec::file("a.pcap", &pcap_of(1, &[b"a0"]))]);
        let (_tmp, path) = written("set.tar", &outer)?;
        let refused = resolved_after_removal(&path, &pointer(&format!("{path}/b.pcap"), 0))?;
        let Err(ResolveError::Unreadable { cause, .. }) = refused else {
            return Err(format!("resolved: {refused:?}").into());
        };
        assert!(
            cause.contains("holds no member named 'b.pcap'"),
            "the refusal names the member: {cause}"
        );
        Ok(())
    }

    #[test]
    fn a_path_below_an_opened_capture_is_not_a_member() -> Result<(), TestError> {
        let (_tmp, path) = written("a.pcap", &pcap_of(1, &[b"zero"]))?;
        let source = format!("{path}/inner.pcap");
        let refused = resolve_opened(&pointer(&source, 0), open_source_up_front(&source));
        assert!(
            matches!(refused, Err(ResolveError::Unreadable { .. })),
            "a capture is not an archive, so the label leads nowhere: {refused:?}"
        );
        Ok(())
    }

    #[test]
    fn a_uprobe_pointer_is_refused_before_the_opened_source_is_read() {
        let mut wanted = pointer("/nonexistent-sipnab-test/a.pcap", 0);
        wanted.kind = FrameSource::Uprobe {
            comm: std::sync::Arc::from("opensips"),
            pid: 7,
        };
        let refused = resolve_opened(&wanted, open_source_up_front(&wanted.source));
        assert!(
            matches!(refused, Err(ResolveError::NeverOnTheWire { pid: 7, .. })),
            "bytes read out of a process were never a frame: {refused:?}"
        );
    }

    /// A pointer whose source is `<archive>/<member>` resolves to that frame
    /// of that member, through a gzip layer and a nested archive alike.
    #[test]
    fn a_pointer_into_an_archive_member_resolves() -> Result<(), TestError> {
        let tmp = tempfile::tempdir().map_err(|e| format!("tmp: {e:?}"))?;
        let a = pcap_of(1, &[b"a-zero", b"a-one"]);
        let b = pcap_of(1, &[b"b-zero", b"b-one", b"b-two"]);
        let inner = build(&[Spec::file("b.pcap.gz", &gzip(&b)?)]);
        let outer = build(&[Spec::file("dir/a.pcap", &a), Spec::file("in.tar", &inner)]);
        let path = tmp.path().join("set.tgz");
        std::fs::write(&path, gzip(&outer)?).map_err(|e| format!("write: {e:?}"))?;
        let root = path.display().to_string();

        let got = resolve(&pointer(&format!("{root}/dir/a.pcap"), 1))
            .map_err(|e| format!("resolves: {e:?}"))?;
        assert_eq!(got, Resolution::Unverified(b"a-one".to_vec()));
        let got = resolve(&pointer(&format!("{root}/in.tar/b.pcap.gz"), 2))
            .map_err(|e| format!("nested: {e:?}"))?;
        assert_eq!(got.bytes(), b"b-two");
        Ok(())
    }

    /// The link type comes back with the bytes, from the member itself: a
    /// pointer into an archive has no file of its own to reopen for it.
    #[test]
    fn the_members_link_type_comes_back_with_the_frame() -> Result<(), TestError> {
        let tmp = tempfile::tempdir().map_err(|e| format!("tmp: {e:?}"))?;
        let cooked = pcap_of(113, &[b"sll-frame"]);
        let path = tmp.path().join("c.tar");
        std::fs::write(&path, build(&[Spec::file("c.pcap", &cooked)]))
            .map_err(|e| format!("write: {e:?}"))?;
        let (res, link_type) =
            resolve_with_link_type(&pointer(&format!("{}/c.pcap", path.display()), 0))
                .map_err(|e| format!("resolves: {e:?}"))?;
        assert_eq!(res.bytes(), b"sll-frame");
        assert_eq!(link_type, 113);
        Ok(())
    }

    /// A label naming no member is refused with the archive and the name, not
    /// "file not found": the archive is right there.
    #[test]
    fn a_label_naming_no_member_is_refused_by_name() -> Result<(), TestError> {
        let tmp = tempfile::tempdir().map_err(|e| format!("tmp: {e:?}"))?;
        let path = tmp.path().join("s.tar");
        std::fs::write(
            &path,
            build(&[Spec::file("real.pcap", &pcap_of(1, &[b"x"]))]),
        )
        .map_err(|e| format!("write: {e:?}"))?;
        let err = resolve(&pointer(&format!("{}/missing.pcap", path.display()), 0))
            .err()
            .ok_or("no such member")?;
        let msg = err.to_string();
        assert!(
            matches!(err, ResolveError::Unreadable { .. }) && msg.contains("no member"),
            "{msg}"
        );
        Ok(())
    }

    /// A member holding fewer frames than the ordinal is `NoSuchFrame`, the
    /// same answer a short file gives.
    #[test]
    fn an_ordinal_past_a_members_end_is_no_such_frame() -> Result<(), TestError> {
        let tmp = tempfile::tempdir().map_err(|e| format!("tmp: {e:?}"))?;
        let path = tmp.path().join("s.tar");
        std::fs::write(&path, build(&[Spec::file("m.pcap", &pcap_of(1, &[b"x"]))]))
            .map_err(|e| format!("write: {e:?}"))?;
        let err = resolve(&pointer(&format!("{}/m.pcap", path.display()), 5))
            .err()
            .ok_or("short")?;
        assert!(
            matches!(
                err,
                ResolveError::NoSuchFrame {
                    frames_present: 1,
                    ..
                }
            ),
            "{err}"
        );
        Ok(())
    }
}

#[cfg(test)]
mod uprobe_origin_tests {
    use super::*;
    use crate::capture::packet::{FrameOrigin, FrameRef, FrameSource};

    /// Any error a test can return; `?` converts into it.
    type TestError = Box<dyn std::error::Error>;

    /// A pointer minted for plaintext lifted out of a process must survive
    /// being written down, because a pointer is only useful once it has left
    /// the process.
    #[test]
    fn a_uprobe_pointer_round_trips_through_its_text_form() -> Result<(), TestError> {
        let minted = FrameRef::uprobe("opensips", 1234, 7);
        let text = minted.to_string();
        assert_eq!(text, "uprobe:opensips/1234#7");

        let parsed =
            parse_pointer(&text).map_err(|e| format!("a minted pointer must parse: {e:?}"))?;
        assert_eq!(parsed.origin.ordinal, 7);
        assert!(
            matches!(parsed.source_kind(), FrameSource::Uprobe { .. }),
            "the kind has to survive the text form, or a resolver cannot tell \
             this apart from a capture file that happens to be named oddly"
        );
        Ok(())
    }

    /// The whole point of the type: following it must refuse, and the refusal
    /// must say the bytes were never on the wire — not that a file is missing.
    #[test]
    fn following_a_uprobe_pointer_refuses_and_says_why() -> Result<(), TestError> {
        let pointer = FrameRef::uprobe("opensips", 1234, 7);
        let err = resolve(&pointer)
            .err()
            .ok_or("there is no frame to resolve to")?;

        let msg = err.to_string();
        assert!(
            matches!(err, ResolveError::NeverOnTheWire { .. }),
            "must be its own refusal, not a missing-file error: {msg}"
        );
        assert!(msg.contains("opensips"), "names the process: {msg}");
        assert!(msg.contains("1234"), "names the pid: {msg}");
        assert!(
            msg.contains("never") || msg.contains("no frame"),
            "says the bytes were never a frame, rather than implying a lookup \
             failed: {msg}"
        );
        Ok(())
    }

    /// A wire pointer must keep resolving exactly as before. This is the
    /// mutation guard: if the new branch swallowed everything, this fails.
    #[test]
    fn a_wire_pointer_is_untouched_by_the_new_kind() -> Result<(), TestError> {
        let wire = FrameRef {
            // Whole frame.
            bytes: None,
            source: std::sync::Arc::from("capture.pcap"),
            origin: FrameOrigin {
                verifiable: false,
                ordinal: 3,
                digest: None,
            },
            kind: FrameSource::Wire,
        };
        assert_eq!(wire.to_string(), "capture.pcap#3");
        let err = resolve(&wire).err().ok_or("no such file here")?;
        assert!(
            matches!(err, ResolveError::Unreadable { .. }),
            "a wire pointer to a missing file is still Unreadable, not the \
             uprobe refusal"
        );
        Ok(())
    }
}
