// SPDX-License-Identifier: MIT OR Apache-2.0

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

/// Follow a pointer back to the frame's bytes.
///
/// # Errors
///
/// Returns [`ResolveError`] rather than bytes whenever the answer would be a
/// guess: the source will not open, it is too short, or the frame there is
/// not the frame the pointer was made against.
pub fn resolve(pointer: &FrameRef) -> Result<Resolution, ResolveError> {
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
    let path = Path::new(&*pointer.source);
    let (mut cap, _guard) =
        super::file::open_offline(path).map_err(|e| ResolveError::Unreadable {
            source: pointer.source.to_string(),
            cause: format!("{e:#}"),
        })?;

    let mut seen: u64 = 0;
    while let Ok(pkt) = cap.next_packet() {
        if seen == pointer.origin.ordinal {
            let bytes = pkt.data.to_vec();
            return Ok(match pointer.origin.digest {
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
            });
        }
        seen += 1;
    }

    Err(ResolveError::NoSuchFrame {
        source: pointer.source.to_string(),
        ordinal: pointer.origin.ordinal,
        frames_present: seen,
    })
}

#[cfg(test)]
mod uprobe_origin_tests {
    use super::*;
    use crate::capture::packet::{FrameOrigin, FrameRef, FrameSource};

    /// A pointer minted for plaintext lifted out of a process must survive
    /// being written down, because a pointer is only useful once it has left
    /// the process.
    #[test]
    fn a_uprobe_pointer_round_trips_through_its_text_form() {
        let minted = FrameRef::uprobe("opensips", 1234, 7);
        let text = minted.to_string();
        assert_eq!(text, "uprobe:opensips/1234#7");

        let parsed = parse_pointer(&text).expect("a minted pointer must parse");
        assert_eq!(parsed.origin.ordinal, 7);
        assert!(
            matches!(parsed.source_kind(), FrameSource::Uprobe { .. }),
            "the kind has to survive the text form, or a resolver cannot tell \
             this apart from a capture file that happens to be named oddly"
        );
    }

    /// The whole point of the type: following it must refuse, and the refusal
    /// must say the bytes were never on the wire — not that a file is missing.
    #[test]
    fn following_a_uprobe_pointer_refuses_and_says_why() {
        let pointer = FrameRef::uprobe("opensips", 1234, 7);
        let err = resolve(&pointer).expect_err("there is no frame to resolve to");

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
    }

    /// A wire pointer must keep resolving exactly as before. This is the
    /// mutation guard: if the new branch swallowed everything, this fails.
    #[test]
    fn a_wire_pointer_is_untouched_by_the_new_kind() {
        let wire = FrameRef {
            source: std::sync::Arc::from("capture.pcap"),
            origin: FrameOrigin {
                verifiable: false,
                ordinal: 3,
                digest: None,
            },
            kind: FrameSource::Wire,
        };
        assert_eq!(wire.to_string(), "capture.pcap#3");
        let err = resolve(&wire).expect_err("no such file here");
        assert!(
            matches!(err, ResolveError::Unreadable { .. }),
            "a wire pointer to a missing file is still Unreadable, not the \
             uprobe refusal"
        );
    }
}
