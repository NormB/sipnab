// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! Frame-erasure handling: which decoding a received frame gets. An erased
//! frame is concealed as an active frame (G.729 clause 4.4, Annex A clause
//! A.4.4) when the previous frame was active; with Annex B, an erased frame
//! after a non-active frame is decoded as untransmitted (clause B.4.5,
//! equation (B.27)). The concealment itself lives with each parameter: LSF
//! repetition in `lsp`, the delay in `adaptive`, random indices in `fixed`,
//! gain attenuation in `gain`.

use crate::Frame;
use crate::bitstream::{SidParams, SpeechParams};

/// How a frame is decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// An active frame: its parameters, or `None` when erased (concealed).
    Voice(Option<SpeechParams>),
    /// A non-active (Annex B) frame: a SID frame's parameters, or `None`
    /// for an untransmitted frame; `erased` when it stands for an erased
    /// frame (clause B.4.5).
    ComfortNoise {
        /// The SID parameters, if any.
        sid: Option<SidParams>,
        /// Whether the frame was erased.
        erased: bool,
    },
}

/// The decision for `frame`, given whether the previous frame was decoded
/// as active.
///
/// # Panics
///
/// Does not panic.
///
/// # Examples
///
/// ```
/// use g729::plc::{decide, Decision};
/// use g729::{Frame, bitstream::SpeechParams};
///
/// // A lost frame after an active one is concealed as an active frame.
/// assert_eq!(decide(Frame::Erased, true), Decision::Voice(None));
///
/// // An active frame is unpacked into its parameters.
/// let frame = [0u8; 10];
/// assert_eq!(
///     decide(Frame::Voice(&frame), false),
///     Decision::Voice(Some(SpeechParams::unpack(&frame)))
/// );
/// ```
pub fn decide(frame: Frame<'_>, previous_active: bool) -> Decision {
    match frame {
        Frame::Voice(b) => Decision::Voice(Some(SpeechParams::unpack(b))),
        Frame::Erased if previous_active || !cfg!(feature = "annex-b") => Decision::Voice(None),
        Frame::Erased => Decision::ComfortNoise {
            sid: None,
            erased: true,
        },
        #[cfg(feature = "annex-b")]
        Frame::Sid(b) => Decision::ComfortNoise {
            sid: Some(SidParams::unpack(b)),
            erased: false,
        },
        #[cfg(feature = "annex-b")]
        Frame::NoTx => Decision::ComfortNoise {
            sid: None,
            erased: false,
        },
        // Without Annex B a comfort-noise frame cannot be decoded; it is
        // concealed like an erased frame.
        #[cfg(not(feature = "annex-b"))]
        Frame::Sid(_) | Frame::NoTx => Decision::Voice(None),
    }
}
