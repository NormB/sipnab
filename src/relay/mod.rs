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
