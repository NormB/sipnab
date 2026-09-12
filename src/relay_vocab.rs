// SPDX-License-Identifier: MIT OR Apache-2.0

//! Relay vocabulary that outlives the relay module.
//!
//! These two enums describe a claim's AUTHOR and its PATH, and an endpoint
//! assertion carries both. That assertion lives in `rtp::stream_store`, which
//! the wasm build compiles, while `crate::relay` is native-only -- a browser
//! analyzer has no control plane to reconcile against. So the vocabulary sits
//! here, where both can see it, and [`crate::relay`] re-exports it so every
//! existing path keeps working.
//!
//! Nothing here depends on a transport, a parser or a socket. That is what
//! makes the split honest rather than a workaround: these are words, and words
//! are portable even where the machinery is not.

/// Which relay implementation asserted something.
///
/// The vocabulary lives HERE, at the seam, and nowhere above it. A consumer
/// prints [`Self::as_str`]; it never matches on a vendor name, which is what
/// keeps `src/mcp/`, `src/output/` and `src/tui/` free of them and what
/// `relay_seam_test` holds in place.
///
/// The distinction is not cosmetic. The two relays have different trust
/// properties and different failure modes, so "a relay said so" stops being a
/// complete answer the moment an estate runs both.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum RelayImplementation {
    /// rtpengine, whose `ng` control plane is encapsulated and can carry
    /// authentication.
    ///
    /// The default, and not an arbitrary one: it is the only relay the query
    /// path has ever spoken to, so a snapshot built before anything named a
    /// relay means this one. A new source of snapshots has to say otherwise.
    #[default]
    Rtpengine,
    /// rtpproxy, whose text control plane is a bare datagram carrying no
    /// credential of any kind.
    Rtpproxy,
}

impl RelayImplementation {
    /// The name this implementation is written under on every output surface.
    ///
    /// One spelling in one place, for the same reason
    /// [`crate::rtp::stream_store::EndpointAssertion::as_str`] has one.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Rtpengine => "rtpengine",
            Self::Rtpproxy => "rtpproxy",
        }
    }
}

/// How a control message reached the capture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlDelivery {
    /// Wrapped in a transport that can carry authentication.
    Encapsulated,
    /// A bare datagram, read off the wire and authenticated by nothing.
    BareDatagram,
}
