// SPDX-License-Identifier: MIT OR Apache-2.0

//! A bounded ring of raw frames, so a live capture can answer a pointer.
//!
//! # The difference this does not paper over
//!
//! A capture file can seek back and hand over the real bytes. A live device or
//! a HEP listener cannot: sipnab holds parsed messages and not frames, which is
//! why the export path re-synthesizes them, and why a pointer into one is
//! refused rather than answered with something plausible.
//!
//! This closes that gap for RECENT frames without pretending it closed it for
//! all of them. The interesting behavior is therefore not the hit — it is the
//! three different misses, because they prompt three different responses:
//!
//! * [`Lookup::Evicted`] — the frame was real and the ring has moved past it.
//!   Ask for a bigger ring, or ask sooner.
//! * [`Lookup::NotSeen`] — the ring has not reached that ordinal. The pointer
//!   is from another run, or the frame has not arrived.
//! * [`Lookup::NotRetained`] — nothing is kept for that source at all.
//!
//! Collapsing those into one "no" would be the same mistake as a check that
//! answers `0` for five different situations, which is the failure this
//! repository has already paid for once.
//!
//! # Why a byte budget
//!
//! An operator sets this to protect memory on a live capture. Counting FRAMES
//! would leave it unbounded in the dimension that matters — a jumbo frame is
//! two orders of magnitude larger than a SIP datagram — so a ring sized by
//! count is a ring whose real footprint depends on the traffic it sees.

use std::collections::{HashMap, VecDeque};

use bytes::Bytes;

/// What the ring can say about one frame.
#[derive(Debug)]
pub enum Lookup {
    /// The frame, exactly as it was read.
    Retained(Bytes),
    /// The frame was held and the ring has since moved past it. `oldest` is
    /// the earliest ordinal still retained for that source, so a caller can
    /// say how far it missed by rather than only that it missed.
    Evicted {
        /// Earliest ordinal still held for this source.
        oldest: u64,
    },
    /// The ring has not reached that ordinal for this source. `newest` is the
    /// latest it has seen, which is what tells "not yet" apart from "never".
    NotSeen {
        /// Latest ordinal seen for this source.
        newest: u64,
    },
    /// Nothing is kept for that source.
    NotRetained,
}

/// One retained frame.
#[derive(Debug)]
struct Held {
    /// Interned source name the frame was read from.
    source: &'static str,
    /// Position within that source.
    ordinal: u64,
    /// The frame, exactly as read.
    bytes: Bytes,
}

/// Per-source bookkeeping, so a miss can say which kind of miss it is.
///
/// `retained` is the ordinals still held FOR THIS SOURCE in insertion order,
/// so eviction reads the new oldest off the front instead of scanning. The
/// first draft scanned the whole queue on every eviction, which is quadratic
/// on a live capture once the ring is full — the exact condition it exists for.
#[derive(Debug, Default)]
struct Seen {
    /// Ordinals still held for this source, oldest first.
    retained: VecDeque<u64>,
    /// Latest ordinal this source has offered, retained or not.
    newest_seen: u64,
}

/// A bounded, insertion-ordered ring of raw frames keyed by source and ordinal.
#[derive(Debug)]
pub struct EvidenceRing {
    /// Most frame bytes this ring may hold, from the operator's flag.
    budget_bytes: usize,
    /// Frame bytes currently held.
    held_bytes: usize,
    /// Every retained frame in arrival order, which is eviction order.
    order: VecDeque<Held>,
    /// Retained frames by source and ordinal, so a hit is one hash lookup.
    index: HashMap<(&'static str, u64), Bytes>,
    /// Per-source bookkeeping, so a miss can say which kind of miss it is.
    seen: HashMap<&'static str, Seen>,
}

impl EvidenceRing {
    /// A ring that will hold at most `budget_bytes` of frame data.
    #[must_use]
    pub fn with_capacity_bytes(budget_bytes: usize) -> Self {
        Self {
            budget_bytes,
            held_bytes: 0,
            order: VecDeque::new(),
            index: HashMap::new(),
            seen: HashMap::new(),
        }
    }

    /// Bytes of frame data currently held.
    #[must_use]
    pub fn retained_bytes(&self) -> usize {
        self.held_bytes
    }

    /// Offer a frame to the ring.
    ///
    /// A frame larger than the WHOLE budget is refused rather than obeyed:
    /// taking it would evict everything else and still overrun, leaving the
    /// ring holding one frame it cannot afford. The budget is the operator's
    /// number and outranks any single frame.
    ///
    /// The newest-seen ordinal advances either way, because the ring saw that
    /// frame go past even when it did not keep it — which is what lets a later
    /// miss say "evicted" rather than "not seen".
    pub fn insert(&mut self, source: &'static str, ordinal: u64, bytes: Bytes) {
        let seen = self.seen.entry(source).or_default();
        seen.newest_seen = seen.newest_seen.max(ordinal);

        if bytes.len() > self.budget_bytes {
            return;
        }
        while self.held_bytes + bytes.len() > self.budget_bytes {
            if !self.evict_oldest() {
                return;
            }
        }

        self.held_bytes += bytes.len();
        self.index.insert((source, ordinal), bytes.clone());
        self.order.push_back(Held {
            source,
            ordinal,
            bytes,
        });
        let seen = self.seen.entry(source).or_default();
        seen.retained.push_back(ordinal);
    }

    /// Drop the oldest retained frame. `false` when there was nothing to drop.
    fn evict_oldest(&mut self) -> bool {
        let Some(held) = self.order.pop_front() else {
            return false;
        };
        self.index.remove(&(held.source, held.ordinal));
        self.held_bytes = self.held_bytes.saturating_sub(held.bytes.len());
        // Frames arrive in ordinal order per source, so the one leaving the
        // global queue is the one at the front of that source's queue. Popping
        // rather than scanning is what keeps eviction O(1).
        if let Some(seen) = self.seen.get_mut(held.source) {
            if seen.retained.front() == Some(&held.ordinal) {
                seen.retained.pop_front();
            } else {
                // Out of order, which the frame counters make impossible --
                // but a queue that silently disagreed with the index would
                // make a retained frame unfindable, so it is repaired rather
                // than assumed.
                if let Some(pos) = seen.retained.iter().position(|o| *o == held.ordinal) {
                    seen.retained.remove(pos);
                }
            }
        }
        true
    }

    /// What can be said about one frame.
    #[must_use]
    pub fn lookup(&self, source: &str, ordinal: u64) -> Lookup {
        // `get_key_value` hands back the interned `&'static str` the index is
        // keyed on, so the hit path is one hash lookup rather than a scan of
        // every retained frame -- which is what the first draft did, on the
        // one call a resolver makes per pointer.
        let Some((interned, seen)) = self.seen.get_key_value(source) else {
            return Lookup::NotRetained;
        };
        if let Some(bytes) = self.index.get(&(*interned, ordinal)) {
            return Lookup::Retained(bytes.clone());
        }
        let Some(oldest) = seen.retained.front().copied() else {
            return Lookup::NotRetained;
        };
        if ordinal > seen.newest_seen {
            return Lookup::NotSeen {
                newest: seen.newest_seen,
            };
        }
        Lookup::Evicted { oldest }
    }
}
