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
    let (source, ordinal) = text.rsplit_once('#').ok_or_else(malformed)?;
    if source.is_empty() {
        return Err(malformed());
    }
    let ordinal: u64 = ordinal.parse().map_err(|_| malformed())?;
    Ok(FrameRef {
        source: std::sync::Arc::from(source),
        origin: super::packet::FrameOrigin {
            ordinal,
            digest: None,
        },
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
