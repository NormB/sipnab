// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! The key log entries a TLS decryptor holds, grouped by client random and
//! bounded in number.
//!
//! The decryptor used to keep every entry in one `Vec` for the life of the
//! run and regroup all of them by client random each time a key arrived. A
//! `--keylog-watch` run or a capture with Decryption Secrets Blocks adds keys
//! for as long as it runs, so the memory grew without a bound and the work per
//! new key grew with every key before it. This store keeps the entries grouped
//! as they arrive, remembers which client randoms need a session derived, and
//! holds at most a fixed number of entries.

use indexmap::{IndexMap, IndexSet};

use super::tls::KeyLogEntry;

/// One TLS client random, the key the store groups entries by.
pub(crate) type ClientRandom = [u8; 32];

/// Key log entries grouped by client random, oldest client random first.
#[derive(Debug, Default)]
pub(crate) struct KeylogStore {
    /// The entries of each client random, in the order they arrived.
    groups: IndexMap<ClientRandom, Vec<KeyLogEntry>>,
    /// Entries in `groups`, kept so the bound costs no walk.
    held: usize,
    /// Entries whose client random is not 32 bytes. No session can come of
    /// one, so it is counted and not kept.
    odd_length: usize,
    /// Every entry given to the store, kept or not.
    loaded: usize,
    /// Most entries `groups` may hold.
    limit: usize,
    /// Client randoms whose session is to be derived, or derived again.
    dirty: IndexSet<ClientRandom>,
    /// Whether every client random without a session is to be tried again,
    /// because a handshake that any of them may fall back to arrived.
    every_unkeyed_dirty: bool,
    /// Entries dropped by the bound while no session held their keys.
    lost: u64,
    /// Whether the bound dropped any entry at all.
    pruned_any: bool,
}

impl KeylogStore {
    /// An empty store that holds at most `limit` entries.
    pub(crate) fn with_limit(limit: usize) -> Self {
        Self {
            limit,
            ..Self::default()
        }
    }

    /// A store holding the entries of a key log read at startup.
    ///
    /// Holds every entry of that file, however many: the file is the one the
    /// operator named, its size is known before the run starts, and dropping
    /// part of it would leave records unreadable that the operator supplied
    /// keys for. The bound is the larger of `limit` and the file's entry
    /// count, so only keys that arrive during the run can be dropped.
    pub(crate) fn from_startup(entries: Vec<KeyLogEntry>, limit: usize) -> Self {
        let mut store = Self::with_limit(limit.max(entries.len()));
        for entry in entries {
            store.push(entry);
        }
        store
    }

    /// Add one entry and mark its client random for derivation.
    ///
    /// # Returns
    ///
    /// Whether the entry was kept: an entry whose client random is not 32
    /// bytes is counted and dropped. The bound is applied by
    /// [`Self::enforce_limit`], not here, because only the decryptor knows
    /// which client randoms already have a session.
    pub(crate) fn push(&mut self, entry: KeyLogEntry) -> bool {
        self.loaded += 1;
        let Ok(cr) = ClientRandom::try_from(entry.client_random.as_slice()) else {
            self.odd_length += 1;
            return false;
        };
        self.groups.entry(cr).or_default().push(entry);
        self.held += 1;
        self.dirty.insert(cr);
        true
    }

    /// Every entry given to the store since the run started, whatever became
    /// of it.
    pub(crate) fn loaded(&self) -> usize {
        self.loaded
    }

    /// Entries the store holds now.
    #[cfg(test)]
    pub(crate) fn held(&self) -> usize {
        self.held
    }

    /// Most entries the store holds: the bound it was given, or the entry
    /// count of a larger key log read at startup.
    pub(crate) fn limit(&self) -> usize {
        self.limit
    }

    /// Whether no entry was ever given to the store.
    pub(crate) fn is_empty(&self) -> bool {
        self.loaded == 0
    }

    /// The entries of client random `cr`, oldest first.
    pub(crate) fn group(&self, cr: &ClientRandom) -> Option<&[KeyLogEntry]> {
        self.groups.get(cr).map(Vec::as_slice)
    }

    /// Mark `cr` for derivation, when the store holds entries for it.
    pub(crate) fn mark(&mut self, cr: &ClientRandom) {
        if self.groups.contains_key(cr) {
            self.dirty.insert(*cr);
        }
    }

    /// Mark every client random that has no session for derivation.
    pub(crate) fn mark_every_unkeyed(&mut self) {
        self.every_unkeyed_dirty = true;
    }

    /// Take the client randoms marked for derivation, oldest first.
    ///
    /// # Arguments
    ///
    /// * `has_session` — whether a client random already has a session; used
    ///   only when [`Self::mark_every_unkeyed`] was called since the last take.
    pub(crate) fn take_dirty(
        &mut self,
        has_session: impl Fn(&ClientRandom) -> bool,
    ) -> Vec<ClientRandom> {
        if std::mem::take(&mut self.every_unkeyed_dirty) {
            for cr in self.groups.keys() {
                if !has_session(cr) {
                    self.dirty.insert(*cr);
                }
            }
        }
        let mut taken: Vec<ClientRandom> = self.dirty.drain(..).collect();
        // Oldest client random first, whatever order the marks came in.
        taken.sort_by_key(|cr| self.groups.get_index_of(cr).unwrap_or(usize::MAX));
        taken
    }

    /// Drop entries until the store is within its bound.
    ///
    /// Drops down to seven eighths of the bound, so a store at its bound does
    /// not walk its groups on every new entry. Client randoms whose session
    /// will not be derived again go first, oldest first: their keys already
    /// live in the session, so dropping them loses nothing. Only when those
    /// are not enough are the oldest other client randoms dropped, and their
    /// entries are counted as lost.
    ///
    /// # Arguments
    ///
    /// * `settled` — whether a client random has a session that will never be
    ///   derived again.
    ///
    /// # Returns
    ///
    /// The entries dropped by this call that no session held.
    pub(crate) fn enforce_limit(&mut self, settled: impl Fn(&ClientRandom) -> bool) -> u64 {
        if self.held <= self.limit {
            return 0;
        }
        self.pruned_any = true;
        let target = self.limit - self.limit / 8;
        let mut held = self.held;
        let dirty = &mut self.dirty;
        self.groups.retain(|cr, entries| {
            if held > target && settled(cr) {
                held -= entries.len();
                dirty.shift_remove(cr);
                return false;
            }
            true
        });
        let mut lost = 0u64;
        self.groups.retain(|cr, entries| {
            if held > target {
                held -= entries.len();
                lost += entries.len() as u64;
                dirty.shift_remove(cr);
                return false;
            }
            true
        });
        self.held = held;
        self.lost += lost;
        lost
    }

    /// Drop every entry of `cr` and its mark, without counting them as lost:
    /// the caller dropped the session they keyed and counts that.
    pub(crate) fn forget(&mut self, cr: &ClientRandom) {
        if let Some(entries) = self.groups.shift_remove(cr) {
            self.held -= entries.len();
            self.pruned_any = true;
        }
        self.dirty.shift_remove(cr);
    }

    /// Entries the bound dropped while no session held their keys.
    pub(crate) fn lost(&self) -> u64 {
        self.lost
    }

    /// How many entries carry a client random `known` does not know, entries
    /// of an odd length included.
    ///
    /// # Returns
    ///
    /// `None` once the bound has dropped an entry: a dropped entry may have
    /// been one of those, and the count would then be short.
    pub(crate) fn unmatched(&self, known: impl Fn(&ClientRandom) -> bool) -> Option<usize> {
        if self.pruned_any {
            return None;
        }
        Some(
            self.odd_length
                + self
                    .groups
                    .iter()
                    .filter(|(cr, _)| !known(cr))
                    .map(|(_, entries)| entries.len())
                    .sum::<usize>(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An entry of `label` for client random `cr`.
    fn entry(cr: u8, label: &str) -> KeyLogEntry {
        KeyLogEntry {
            label: label.to_string(),
            client_random: vec![cr; 32],
            secret: crate::test_material::bytes_for("keylog-store-entry-secret", 48),
        }
    }

    /// The client random every byte of which is `b`.
    fn cr(b: u8) -> ClientRandom {
        [b; 32]
    }

    /// SUCCESS. Entries are grouped by client random in arrival order, and
    /// each new client random is marked once for derivation.
    #[test]
    fn entries_are_grouped_by_client_random_and_marked_once() {
        let mut store = KeylogStore::with_limit(100);
        assert!(store.push(entry(1, "CLIENT_TRAFFIC_SECRET_0")), "kept");
        assert!(store.push(entry(2, "CLIENT_RANDOM")), "kept");
        assert!(store.push(entry(1, "SERVER_TRAFFIC_SECRET_0")), "kept");

        assert_eq!(
            store.group(&cr(1)).map(<[KeyLogEntry]>::len),
            Some(2),
            "two entries for 1"
        );
        assert_eq!(
            store.take_dirty(|_| false),
            vec![cr(1), cr(2)],
            "each marked once, oldest first"
        );
        assert!(
            store.take_dirty(|_| false).is_empty(),
            "a take clears the marks"
        );
        assert_eq!(
            (store.loaded(), store.held()),
            (3, 3),
            "all loaded and held"
        );
    }

    /// SUCCESS. A key arriving for a client random marks only that one, so a
    /// new batch of keys costs work for the batch and not for the whole log.
    #[test]
    fn a_new_entry_marks_only_its_own_client_random() {
        let mut store = KeylogStore::with_limit(100);
        for b in 0..50 {
            store.push(entry(b, "CLIENT_RANDOM"));
        }
        let _ = store.take_dirty(|_| false);

        store.push(entry(7, "CLIENT_RANDOM"));

        assert_eq!(
            store.take_dirty(|_| false),
            vec![cr(7)],
            "only the new key's client random"
        );
    }

    /// SUCCESS. A store past its bound drops client randoms whose sessions
    /// are settled first and loses nothing.
    #[test]
    fn the_bound_drops_settled_client_randoms_first_and_loses_nothing() {
        let mut store = KeylogStore::with_limit(8);
        for b in 0..9 {
            store.push(entry(b, "CLIENT_RANDOM"));
        }

        let lost = store.enforce_limit(|c| c[0] % 2 == 0);

        assert_eq!(lost, 0, "settled groups were enough");
        assert_eq!(store.held(), 7, "down to seven eighths of the bound");
        assert!(store.group(&cr(0)).is_none(), "the oldest settled one went");
        assert!(store.group(&cr(1)).is_some(), "an unsettled one stays");
        assert_eq!(store.lost(), 0, "nothing lost");
    }

    /// SUCCESS. Marks are handed out oldest client random first even when the
    /// marks came newest first.
    #[test]
    fn marks_are_taken_oldest_client_random_first() {
        let mut store = KeylogStore::with_limit(100);
        for b in 0..3 {
            store.push(entry(b, "CLIENT_RANDOM"));
        }
        let _ = store.take_dirty(|_| false);
        store.mark(&cr(2));
        store.mark(&cr(0));

        assert_eq!(
            store.take_dirty(|_| false),
            vec![cr(0), cr(2)],
            "arrival order"
        );
    }

    /// FAILURE. When settled client randoms are not enough, the oldest others
    /// go and are counted as lost.
    #[test]
    fn the_bound_counts_the_entries_it_drops_before_a_session_held_them() {
        let mut store = KeylogStore::with_limit(8);
        for b in 0..9 {
            store.push(entry(b, "CLIENT_RANDOM"));
        }

        let lost = store.enforce_limit(|_| false);

        assert_eq!(lost, 2, "two of the oldest dropped");
        assert_eq!(store.lost(), 2, "and counted");
        assert!(
            store.group(&cr(0)).is_none() && store.group(&cr(1)).is_none(),
            "oldest first"
        );
        assert!(store.group(&cr(8)).is_some(), "the newest stays");
        assert_eq!(
            store.take_dirty(|_| false).len(),
            7,
            "a dropped group is not handed out"
        );
    }

    /// FAILURE. An entry whose client random is not 32 bytes is counted as
    /// loaded and unmatched, and not kept.
    #[test]
    fn an_entry_with_an_odd_length_client_random_is_counted_not_kept() {
        let mut store = KeylogStore::with_limit(100);
        let mut odd = entry(1, "CLIENT_RANDOM");
        odd.client_random.truncate(16);

        assert!(!store.push(odd), "not kept");
        assert_eq!((store.loaded(), store.held()), (1, 0), "loaded, not held");
        assert_eq!(store.unmatched(|_| true), Some(1), "unmatched");
        assert!(store.take_dirty(|_| false).is_empty(), "nothing to derive");
    }

    /// FAILURE. Once the bound dropped an entry, the unmatched count is not
    /// known any more.
    #[test]
    fn the_unmatched_count_is_unknown_once_the_bound_dropped_an_entry() {
        let mut store = KeylogStore::with_limit(2);
        for b in 0..3 {
            store.push(entry(b, "CLIENT_RANDOM"));
        }
        assert_eq!(store.unmatched(|_| false), Some(3), "known before the drop");

        let _ = store.enforce_limit(|_| true);

        assert_eq!(store.unmatched(|_| false), None, "unknown after it");
    }

    /// EDGE. A store at exactly its bound drops nothing.
    #[test]
    fn a_store_at_its_bound_drops_nothing() {
        let mut store = KeylogStore::with_limit(4);
        for b in 0..4 {
            store.push(entry(b, "CLIENT_RANDOM"));
        }

        assert_eq!(store.enforce_limit(|_| false), 0, "nothing lost");
        assert_eq!(store.held(), 4, "all held");
        assert_eq!(
            store.unmatched(|_| false),
            Some(4),
            "the count is still known"
        );
    }

    /// EDGE. A key log read at startup that is larger than the bound is held
    /// whole; only keys that arrive later can be dropped.
    #[test]
    fn a_startup_key_log_larger_than_the_bound_is_held_whole() {
        let entries: Vec<KeyLogEntry> = (0..10).map(|b| entry(b, "CLIENT_RANDOM")).collect();
        let mut store = KeylogStore::from_startup(entries, 4);

        assert_eq!(
            store.enforce_limit(|_| false),
            0,
            "the file is within its own bound"
        );
        assert_eq!(store.held(), 10, "held whole");

        store.push(entry(10, "CLIENT_RANDOM"));
        assert!(
            store.enforce_limit(|_| false) > 0,
            "a key past it is a drop"
        );
    }

    /// EDGE. A handshake that client randoms without a session may fall back
    /// to marks every one of them, and none that has a session.
    #[test]
    fn marking_every_unkeyed_client_random_skips_those_with_a_session() {
        let mut store = KeylogStore::with_limit(100);
        for b in 0..4 {
            store.push(entry(b, "CLIENT_RANDOM"));
        }
        let _ = store.take_dirty(|_| false);

        store.mark_every_unkeyed();

        assert_eq!(
            store.take_dirty(|c| c[0] < 2),
            vec![cr(2), cr(3)],
            "the two without a session"
        );
        assert!(
            store.take_dirty(|_| false).is_empty(),
            "the flag is cleared by the take"
        );
    }

    /// EDGE. Forgetting a client random drops its entries and its mark, and
    /// does not count them as lost.
    #[test]
    fn forgetting_a_client_random_drops_it_without_counting_a_loss() {
        let mut store = KeylogStore::with_limit(100);
        store.push(entry(1, "CLIENT_RANDOM"));
        store.push(entry(2, "CLIENT_RANDOM"));

        store.forget(&cr(1));

        assert!(store.group(&cr(1)).is_none(), "its entries are gone");
        assert_eq!(store.held(), 1, "one entry left");
        assert_eq!(store.lost(), 0, "not a loss");
        assert_eq!(store.take_dirty(|_| false), vec![cr(2)], "its mark is gone");
        assert_eq!(
            store.unmatched(|_| false),
            None,
            "the unmatched count is not known"
        );
    }

    /// EDGE. Marking a client random the store holds no entry for is a no-op.
    #[test]
    fn marking_a_client_random_without_entries_does_nothing() {
        let mut store = KeylogStore::with_limit(100);
        store.mark(&cr(9));
        assert!(store.take_dirty(|_| false).is_empty(), "nothing marked");
    }

    /// SUCCESS. The entries of one client random are handed back oldest
    /// first, so the newest secret of a label is the last one.
    #[test]
    fn a_group_keeps_its_entries_in_arrival_order() {
        let mut store = KeylogStore::with_limit(100);
        for label in [
            "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
            "CLIENT_TRAFFIC_SECRET_0",
            "EXPORTER_SECRET",
        ] {
            store.push(entry(3, label));
        }

        let labels: Vec<&str> = store
            .group(&cr(3))
            .unwrap_or_default()
            .iter()
            .map(|e| e.label.as_str())
            .collect();
        assert_eq!(
            labels,
            [
                "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
                "CLIENT_TRAFFIC_SECRET_0",
                "EXPORTER_SECRET"
            ],
            "arrival order within the group"
        );
    }

    /// SUCCESS. A store within its bound is left alone: nothing dropped, no
    /// mark taken away, and the unmatched count stays known.
    #[test]
    fn a_store_within_its_bound_keeps_its_marks_and_its_count() {
        let mut store = KeylogStore::with_limit(10);
        for b in 0..5 {
            store.push(entry(b, "CLIENT_RANDOM"));
        }

        assert_eq!(store.enforce_limit(|_| true), 0, "nothing dropped");
        assert_eq!(store.take_dirty(|_| false).len(), 5, "every mark is kept");
        assert_eq!(store.unmatched(|_| false), Some(5), "the count is known");
    }

    /// SUCCESS. The unmatched count is the entries of client randoms nobody
    /// knows plus the entries of an odd length.
    #[test]
    fn the_unmatched_count_adds_unknown_client_randoms_and_odd_entries() {
        let mut store = KeylogStore::with_limit(100);
        store.push(entry(1, "CLIENT_TRAFFIC_SECRET_0"));
        store.push(entry(1, "SERVER_TRAFFIC_SECRET_0"));
        store.push(entry(2, "CLIENT_RANDOM"));
        let mut odd = entry(3, "CLIENT_RANDOM");
        odd.client_random.push(0);
        store.push(odd);

        assert_eq!(
            store.unmatched(|c| c[0] == 2),
            Some(3),
            "two entries of client random 1 and the odd one"
        );
    }

    /// SUCCESS. A group the bound dropped is not handed out by a later
    /// take, even after every unkeyed client random was marked.
    #[test]
    fn a_dropped_group_is_not_marked_again_by_a_later_fallback() {
        let mut store = KeylogStore::with_limit(8);
        for b in 0..9 {
            store.push(entry(b, "CLIENT_RANDOM"));
        }
        let _ = store.enforce_limit(|_| false);

        store.mark_every_unkeyed();
        let taken = store.take_dirty(|_| false);

        assert!(
            !taken.contains(&cr(0)) && !taken.contains(&cr(1)),
            "the dropped client randoms are gone: {taken:?}"
        );
        assert_eq!(taken.len(), 7, "the kept ones are marked");
    }

    /// SUCCESS. The bound a store reports is the larger of the one it was
    /// given and the size of a key log read at startup, the bound the store
    /// really keeps.
    #[test]
    fn the_bound_a_store_reports_is_the_one_it_keeps() {
        let small: Vec<KeyLogEntry> = (0..3).map(|b| entry(b, "CLIENT_RANDOM")).collect();
        let large: Vec<KeyLogEntry> = (0..9).map(|b| entry(b, "CLIENT_RANDOM")).collect();

        assert_eq!(KeylogStore::with_limit(6).limit(), 6, "the bound given");
        assert_eq!(
            KeylogStore::from_startup(small, 6).limit(),
            6,
            "a small file keeps the bound given"
        );
        assert_eq!(
            KeylogStore::from_startup(large, 6).limit(),
            9,
            "a larger file is the bound"
        );
    }

    /// SUCCESS. Pushing keeps `loaded` and `held` in step across many client
    /// randoms with more than one entry each.
    #[test]
    fn loaded_and_held_count_every_kept_entry() {
        let mut store = KeylogStore::with_limit(1000);
        for b in 0..40u8 {
            for label in ["CLIENT_TRAFFIC_SECRET_0", "SERVER_TRAFFIC_SECRET_0"] {
                assert!(store.push(entry(b, label)), "a 32-byte entry is kept");
            }
        }
        assert_eq!(
            (store.loaded(), store.held()),
            (80, 80),
            "every entry counted"
        );
        assert!(!store.is_empty(), "the store has entries");
    }

    /// FAILURE. Losses add up across calls to the bound.
    #[test]
    fn losses_add_up_across_calls() {
        let mut store = KeylogStore::with_limit(8);
        for b in 0..9 {
            store.push(entry(b, "CLIENT_RANDOM"));
        }
        let first = store.enforce_limit(|_| false);
        for b in 9..11 {
            store.push(entry(b, "CLIENT_RANDOM"));
        }
        let second = store.enforce_limit(|_| false);

        assert_eq!((first, second), (2, 2), "each call drops down to seven");
        assert_eq!(store.lost(), 4, "the total is kept");
    }

    /// FAILURE. A dropped client random with several entries counts each
    /// entry as lost, not one per client random.
    #[test]
    fn a_dropped_group_counts_every_entry_it_held() {
        let mut store = KeylogStore::with_limit(8);
        for label in [
            "CLIENT_TRAFFIC_SECRET_0",
            "SERVER_TRAFFIC_SECRET_0",
            "EXPORTER_SECRET",
        ] {
            store.push(entry(0, label));
        }
        for b in 1..7 {
            store.push(entry(b, "CLIENT_RANDOM"));
        }

        let lost = store.enforce_limit(|_| false);

        assert_eq!(lost, 3, "the three entries of the oldest client random");
        assert_eq!(store.held(), 6, "the six others are kept");
    }

    /// FAILURE. An entry with an empty client random is counted and not kept.
    #[test]
    fn an_entry_with_an_empty_client_random_is_counted_not_kept() {
        let mut store = KeylogStore::with_limit(100);
        let mut empty = entry(1, "CLIENT_RANDOM");
        empty.client_random.clear();

        assert!(!store.push(empty), "not kept");
        assert_eq!((store.loaded(), store.held()), (1, 0), "loaded, not held");
        assert!(!store.is_empty(), "the store was given an entry");
    }

    /// FAILURE. An entry with a client random one byte too long is counted
    /// and not kept, and marks nothing.
    #[test]
    fn an_entry_with_a_33_byte_client_random_is_counted_not_kept() {
        let mut store = KeylogStore::with_limit(100);
        let mut long = entry(1, "CLIENT_RANDOM");
        long.client_random.push(1);

        assert!(!store.push(long), "not kept");
        assert!(
            store.group(&cr(1)).is_none(),
            "no group for its first 32 bytes"
        );
        assert!(store.take_dirty(|_| false).is_empty(), "nothing marked");
    }

    /// FAILURE. With nothing settled, the bound drops the oldest client
    /// randoms even when they are marked, and their marks go with them.
    #[test]
    fn the_bound_drops_marked_client_randoms_when_nothing_is_settled() {
        let mut store = KeylogStore::with_limit(4);
        for b in 0..5 {
            store.push(entry(b, "CLIENT_RANDOM"));
        }

        assert_eq!(store.enforce_limit(|_| false), 1, "one dropped");
        assert_eq!(
            store.take_dirty(|_| false),
            vec![cr(1), cr(2), cr(3), cr(4)],
            "the oldest mark went with its group"
        );
    }

    /// EDGE. A store with a bound of zero drops every entry it is given.
    #[test]
    fn a_store_with_a_zero_bound_holds_nothing() {
        let mut store = KeylogStore::with_limit(0);
        store.push(entry(1, "CLIENT_RANDOM"));
        store.push(entry(2, "CLIENT_RANDOM"));

        assert_eq!(store.enforce_limit(|_| false), 2, "both dropped");
        assert_eq!(store.held(), 0, "nothing held");
    }

    /// EDGE. A bound of one keeps one entry: seven eighths of one rounds
    /// to one.
    #[test]
    fn a_store_with_a_bound_of_one_keeps_one_entry() {
        let mut store = KeylogStore::with_limit(1);
        store.push(entry(1, "CLIENT_RANDOM"));
        store.push(entry(2, "CLIENT_RANDOM"));

        assert_eq!(store.enforce_limit(|_| false), 1, "one dropped");
        assert!(store.group(&cr(2)).is_some(), "the newest is the one kept");
    }

    /// EDGE. A group larger than the excess goes whole, so the store may end
    /// below seven eighths of its bound; a group is never split.
    #[test]
    fn a_group_is_dropped_whole_even_past_the_target() {
        let mut store = KeylogStore::with_limit(8);
        for i in 0..5 {
            store.push(entry(0, &format!("LABEL_{i}")));
        }
        for b in 1..5 {
            store.push(entry(b, "CLIENT_RANDOM"));
        }

        assert_eq!(store.enforce_limit(|_| false), 5, "the five-entry group");
        assert_eq!(store.held(), 4, "four left, below the target of seven");
    }

    /// EDGE. Forgetting a client random the store never held changes nothing,
    /// and the unmatched count stays known.
    #[test]
    fn forgetting_an_unknown_client_random_changes_nothing() {
        let mut store = KeylogStore::with_limit(100);
        store.push(entry(1, "CLIENT_RANDOM"));

        store.forget(&cr(9));

        assert_eq!(store.held(), 1, "nothing dropped");
        assert_eq!(
            store.unmatched(|_| false),
            Some(1),
            "the count is still known"
        );
    }

    /// EDGE. A key log read at startup that is empty gives an empty store
    /// with the bound it was given.
    #[test]
    fn an_empty_startup_key_log_gives_an_empty_store() {
        let store = KeylogStore::from_startup(Vec::new(), 5);

        assert!(store.is_empty(), "empty");
        assert_eq!(store.limit(), 5, "the bound given");
        assert_eq!(store.unmatched(|_| false), Some(0), "nothing unmatched");
    }
}
