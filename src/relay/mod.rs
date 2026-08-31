// SPDX-License-Identifier: MIT OR Apache-2.0

//! The media relay seam.
//!
//! What sipnab needs from ANY relay, and nothing about which one answered.
//! A relay implementation lives under its own module -- `src/rtpengine/` is
//! the first -- and reaches this contract from below. Everything above it,
//! `src/mcp/`, `src/output/`, `src/tui/`, consumes attributions and must never
//! learn a vendor name; `relay_seam_test` is what holds that.
//!
//! # What a relay implementation owes
//!
//! Four things, and this list is the definition rather than a summary of one:
//!
//! 1. **Decode a control message** into [`types::ControlReply`].
//! 2. **Say whether a command creates media**, so an unattributed one can be
//!    counted rather than passed over -- see [`note_media_creating_command`].
//! 3. **Yield endpoints with an `EndpointAssertion`**, so a consumer can tell a
//!    relay's claim from a claim the two parties made in SDP.
//! 4. **Report its own authentication status**, because "the relay told us" and
//!    "a datagram claiming to be the relay told us" are different facts.
//!
//! # What it must NOT be asked for
//!
//! Anything that changes a production relay. [`reconcile::ReadOnlyRelay`] has
//! two methods and no third: rtpengine's ng protocol also carries `offer`,
//! `answer`, `delete` and `start recording`, and none is reachable from here.
//! Adding one means adding a trait method -- a visible act in a diff rather
//! than an oversight at a call site.

pub mod reconcile;
pub mod types;

use std::sync::atomic::{AtomicU64, Ordering};

/// How many media-creating commands were seen without being attributed.
///
/// A plain counter, deliberately: RE5 attributes recording streams from
/// rtpengine's recording spool, not by decoding these commands, so what is
/// owed here is a HONEST COUNT and not an attribution. A run that saw
/// `start recording` and says nothing is the failure this project already
/// named once -- a forensics tool that cannot say what it did not attribute.
static MEDIA_CREATING_SEEN: AtomicU64 = AtomicU64::new(0);

/// Record that a media-creating command went past unattributed.
pub fn note_media_creating_command() {
    MEDIA_CREATING_SEEN.fetch_add(1, Ordering::Relaxed);
}

/// How many media-creating commands this process has seen.
#[must_use]
pub fn media_creating_commands_seen() -> u64 {
    MEDIA_CREATING_SEEN.load(Ordering::Relaxed)
}

/// Reset the counter. Test-only: the tally is process-global.
#[cfg(test)]
pub fn reset_media_creating_count() {
    MEDIA_CREATING_SEEN.store(0, Ordering::Relaxed);
}

/// Decodes a captured datagram as a relay control message.
///
/// Declared here and implemented BELOW, which is the direction the seam
/// requires: an implementation reaches up to satisfy this, and the composition
/// root chooses which one. A factory living here would make the seam import its
/// own implementation, and a seam that does that cannot take a second one.
pub trait ControlDecoder: Send + Sync {
    /// Decode one datagram, or `None` when it is not a control message.
    ///
    /// `dst_port` is passed because whether a sniffed message is believed at
    /// all can depend on where it landed -- a question only the implementation
    /// can answer, and one the caller must not have to know to ask.
    fn decode(&self, payload: &[u8], dst_port: u16) -> Option<DecodedControl>;
}

/// How a control message reached the capture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlDelivery {
    /// Wrapped in a transport that can carry authentication.
    Encapsulated,
    /// A bare datagram, read off the wire and authenticated by nothing.
    BareDatagram,
}

/// One decoded control message, described without naming who speaks it.
///
/// The fields are the questions an analyst asks of a control message -- what
/// was commanded, about which call, carrying how much SDP. Every relay protocol
/// answers those; none of them is a property of one implementation.
#[derive(Debug, Clone)]
pub struct ControlMessage {
    /// The verb, as the relay spells it.
    pub command: Option<String>,
    /// The call the message names, where it names one.
    pub call_id: Option<String>,
    /// How much SDP the message carries, where it carries any.
    pub sdp_bytes: Option<usize>,
}

/// A decoded control datagram and everything known about how it arrived.
#[derive(Debug, Clone)]
pub struct DecodedControl {
    /// Which path carried it.
    pub delivery: ControlDelivery,
    /// What it said.
    pub message: ControlMessage,
    /// The correlation identifier, which names the call on a REPLY.
    pub correlation_id: Option<String>,
    /// Whether it landed on a port a sniffed mirror is believed on.
    ///
    /// `None` where the question does not apply, which is not the same as
    /// `Some(false)`: a bare datagram is not believed on any port.
    pub on_believed_mirror_port: Option<bool>,
}
