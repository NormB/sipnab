// SPDX-License-Identifier: MIT OR Apache-2.0

//! Capture identity and store generation: the primitive that lets a consumer
//! tell "the data changed" from "the data is a different capture".
//!
//! # The gap this closes
//!
//! [`DialogStore::generation`](crate::sip::dialog_store::DialogStore::generation)
//! and [`StreamStore::generation`](crate::rtp::stream_store::StreamStore::generation)
//! are bumped by every mutating method, and until now neither reached the wire.
//! A `/v1/dialogs` poller therefore saw a dialog set change completely between
//! two requests with nothing to say the second answer described a different
//! file. The counters answer *how many times the store changed*; they cannot
//! answer *which capture this is*, because they restart from a store that was
//! cleared. Pairing them with an instance id answers both.
//!
//! # Shared on purpose
//!
//! **This is one primitive with three consumers, not an `open_capture`
//! detail.** Anything that reuses it should extend this module rather than
//! mint a second identity:
//!
//! * `open_capture` (built) rotates the instance the moment it clears the
//!   stores, so every later answer names the capture it came from.
//! * Write-back tools (approved, `docs/design/mcp-write-back.md`) need a
//!   compare-and-set token: [`CaptureEtag`] is that token, and
//!   [`CaptureEtag::from_str`] parses one back off the wire.
//! * Packet-level provenance (`docs/design/deferred-and-declined.md` §1) needs
//!   a capture-instance identity to bind a packet reference to. That is
//!   [`CaptureEtag::instance`], which stays stable for the life of one loaded
//!   capture while the generations move under it.
//!
//! # What an id promises
//!
//! Only this: two answers carrying the same instance describe the same loaded
//! capture, and two carrying different instances do not. The value is unique
//! within a process and, through the process id and start time, distinct
//! across restarts on one host. It is not a content hash and not a UUID —
//! nothing may infer file identity from it.

use std::str::FromStr;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

use serde::Serialize;

/// Capture instances minted by this process, so each rotation gets a new id.
static MINTED: AtomicU64 = AtomicU64::new(0);

/// Per-process prefix shared by every instance id this process mints.
static ORIGIN: OnceLock<String> = OnceLock::new();

/// The per-process id prefix: process id and start time, both hex.
///
/// Two runs on one host differ by process id; a reused process id after a
/// reboot differs by start time. Neither is a security property — the prefix
/// exists so a poller reconnecting to a *restarted* server sees a different
/// instance rather than the same "1" it held before.
fn origin() -> &'static str {
    ORIGIN.get_or_init(|| {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        format!("{:x}{:x}", std::process::id(), nanos)
    })
}

/// Mint the next capture-instance id for this process.
fn mint() -> String {
    let n = MINTED.fetch_add(1, Ordering::Relaxed) + 1;
    format!("{}-{n}", origin())
}

/// The identity of the capture a server currently holds.
///
/// Keep one of these beside whatever holds the stores, and [`rotate`] it in
/// the same critical section that clears them: a reader that sees an emptied
/// store and the old instance has been told the wrong thing.
///
/// [`rotate`]: Self::rotate
#[derive(Debug, Clone)]
pub struct CaptureIdentity {
    /// The current instance id, replaced on every rotation.
    instance: String,
}

impl CaptureIdentity {
    /// Mint the first identity of a capture.
    #[must_use]
    pub fn new() -> Self {
        Self { instance: mint() }
    }

    /// The current instance id.
    #[must_use]
    pub fn instance(&self) -> &str {
        &self.instance
    }

    /// Replace the instance because a different capture is now loaded.
    ///
    /// # Returns
    ///
    /// The new instance id, so a caller can report it without a second read.
    pub fn rotate(&mut self) -> &str {
        self.instance = mint();
        &self.instance
    }

    /// Pair this instance with the two store generations.
    ///
    /// # Arguments
    ///
    /// * `dialog_generation` — `DialogStore::generation()`.
    /// * `stream_generation` — `StreamStore::generation()`.
    #[must_use]
    pub fn etag(&self, dialog_generation: u64, stream_generation: u64) -> CaptureEtag {
        CaptureEtag {
            instance: self.instance.clone(),
            dialog_generation,
            stream_generation,
        }
    }
}

impl Default for CaptureIdentity {
    fn default() -> Self {
        Self::new()
    }
}

/// Which capture an answer came from, and which revision of its stores.
///
/// Compare two of these to learn what changed: a different `instance` means a
/// different capture and every cursor, index and Call-ID from the earlier
/// answer is meaningless; the same instance with a higher generation means the
/// same capture grew.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "mcp", derive(rmcp::schemars::JsonSchema))]
#[cfg_attr(feature = "mcp", schemars(crate = "rmcp::schemars"))]
pub struct CaptureEtag {
    /// Identifies the loaded capture. Opaque; compare it, never parse it.
    pub instance: String,
    /// `DialogStore` mutations since it was created or cleared.
    pub dialog_generation: u64,
    /// `StreamStore` mutations since it was created or cleared.
    pub stream_generation: u64,
}

impl CaptureEtag {
    /// Whether `other` describes a different capture rather than a later
    /// revision of this one.
    ///
    /// Worth its own name because the two cases need opposite handling: a
    /// grown store means re-read, a swapped capture means discard and start
    /// again.
    #[must_use]
    pub fn is_different_capture(&self, other: &Self) -> bool {
        self.instance != other.instance
    }
}

impl std::fmt::Display for CaptureEtag {
    /// `<instance>:<dialog generation>.<stream generation>` — one token, so a
    /// consumer with a single header or a single string field can carry the
    /// whole identity.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{}.{}",
            self.instance, self.dialog_generation, self.stream_generation
        )
    }
}

impl FromStr for CaptureEtag {
    type Err = String;

    /// Parse the [`Display`](std::fmt::Display) form back.
    ///
    /// # Errors
    ///
    /// Names the token and what was expected. A caller handing back a
    /// mangled etag is asking for a compare-and-set against something it
    /// cannot describe, and guessing at the intent is how a write lands on
    /// the wrong revision.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (instance, generations) = s.split_once(':').ok_or_else(|| {
            format!("'{s}' is not an etag: expected <instance>:<dialogs>.<streams>")
        })?;
        let (dialogs, streams) = generations.split_once('.').ok_or_else(|| {
            format!("'{s}' has no generation pair: expected <instance>:<dialogs>.<streams>")
        })?;
        if instance.is_empty() {
            return Err(format!("'{s}' has an empty instance id"));
        }
        Ok(Self {
            instance: instance.to_string(),
            dialog_generation: dialogs
                .parse()
                .map_err(|_| format!("'{dialogs}' is not a dialog generation"))?,
            stream_generation: streams
                .parse()
                .map_err(|_| format!("'{streams}' is not a stream generation"))?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two identities minted in one process must differ, or a swap is
    /// invisible to exactly the consumer this exists for.
    #[test]
    fn every_minted_instance_is_distinct() {
        let a = CaptureIdentity::new();
        let b = CaptureIdentity::new();
        assert_ne!(a.instance(), b.instance());
    }

    /// Rotation is the swap signal: the id before and after must not match.
    #[test]
    fn rotate_replaces_the_instance() {
        let mut id = CaptureIdentity::new();
        let before = id.instance().to_string();
        let after = id.rotate().to_string();
        assert_ne!(before, after, "a rotated identity must not reuse its id");
        assert_eq!(id.instance(), after, "rotate must return what it stored");
    }

    /// The generations travel with the instance, unmodified.
    #[test]
    fn etag_carries_both_store_generations() {
        let id = CaptureIdentity::new();
        let tag = id.etag(42, 7);
        assert_eq!(tag.instance, id.instance());
        assert_eq!(tag.dialog_generation, 42);
        assert_eq!(tag.stream_generation, 7);
    }

    /// A grown store is not a new capture, and the two must not be confused:
    /// one means "read more", the other "throw away every cursor you hold".
    #[test]
    fn a_higher_generation_is_not_a_different_capture() {
        let id = CaptureIdentity::new();
        let before = id.etag(1, 1);
        let after = id.etag(9, 4);
        assert!(!before.is_different_capture(&after));
        assert_ne!(before, after, "the etag itself must still differ");
    }

    /// A rotated identity is a different capture even at the same generation,
    /// which is the case a bare generation counter cannot express: a cleared
    /// store can legitimately be back at a number the previous capture used.
    #[test]
    fn a_rotated_identity_is_a_different_capture_at_the_same_generation() {
        let mut id = CaptureIdentity::new();
        let before = id.etag(3, 3);
        id.rotate();
        let after = id.etag(3, 3);
        assert!(before.is_different_capture(&after));
    }

    /// The string form must survive a round trip, because write-back hands it
    /// back as a compare-and-set token.
    #[test]
    fn etag_round_trips_through_its_string_form() {
        let tag = CaptureIdentity::new().etag(12, 34);
        let text = tag.to_string();
        let parsed: CaptureEtag = text.parse().expect("round trip");
        assert_eq!(parsed, tag, "parsed {text} did not match");
    }

    /// A mangled token is refused rather than defaulted, so a compare-and-set
    /// cannot silently succeed against generation zero.
    #[test]
    fn a_malformed_etag_is_refused() {
        for bad in [
            "", "no-colon", "inst:", "inst:1", "inst:x.1", "inst:1.y", ":1.2",
        ] {
            assert!(
                bad.parse::<CaptureEtag>().is_err(),
                "'{bad}' must not parse as an etag"
            );
        }
    }

    /// The JSON shape is part of the contract: three named fields, so a
    /// consumer can compare the instance without string surgery.
    #[test]
    fn etag_serialises_with_named_fields() {
        let tag = CaptureIdentity::new().etag(5, 6);
        let v = serde_json::to_value(&tag).expect("serialise");
        assert_eq!(v["instance"], tag.instance);
        assert_eq!(v["dialog_generation"], 5);
        assert_eq!(v["stream_generation"], 6);
    }
}
