// SPDX-License-Identifier: MIT OR Apache-2.0

//! A bounded map that evicts its least recently used entry in constant time.
//!
//! Every attacker-keyed map in the security detectors is capped, and each one
//! chose its eviction victim with `min_by_key` over the whole map: ten
//! thousand comparisons per packet once a spoofed-source flood had filled it,
//! on the capture thread, inside `process_parsed_packet`, under both store
//! write locks while every MCP and API reader waited. Front removal from an
//! insertion-ordered `IndexMap`, which the capture module uses for the same
//! job, is not the answer either: `shift_remove_index(0)` decrements every
//! index in the hash table and moves every entry down one slot, the same
//! order of work with a larger constant.
//!
//! This is the textbook structure instead. A hash index maps each key to a
//! slot in a `Vec`, and the slots are threaded on a doubly linked list in
//! recency order. A touch unlinks one slot and relinks it at the tail; an
//! eviction unlinks the head. Both are a handful of index writes whatever the
//! map holds. Removing a slot swaps the last slot into its place, IndexMap's
//! `swap_remove`, and repoints the two neighbors and one index entry that
//! named it, so the `Vec` never has a hole and no `unsafe` is needed.

use std::borrow::Borrow;
use std::collections::HashMap;
use std::hash::Hash;

/// The index that means "no slot": the head's `prev` and the tail's `next`.
const NIL: usize = usize::MAX;

/// One entry, and its place in recency order.
struct Entry<K, V> {
    /// The key, kept here as well as in the index so an eviction of the head
    /// knows which index entry to remove.
    key: K,
    /// The value.
    value: V,
    /// The next-less-recently-used slot, or [`NIL`] at the head.
    prev: usize,
    /// The next-more-recently-used slot, or [`NIL`] at the tail.
    next: usize,
}

/// A map of at most `capacity` entries that evicts the least recently used
/// one to admit a new key.
///
/// "Used" means inserted, or returned by [`Self::get_mut`] or
/// [`Self::get_or_insert_with`]. [`Self::peek`] and [`Self::contains_key`]
/// read without touching, and [`Self::retain`] keeps the order of what it
/// keeps.
pub struct LruMap<K, V> {
    /// Key to slot.
    index: HashMap<K, usize>,
    /// The slots, in no particular order; recency is the list, not the `Vec`.
    entries: Vec<Entry<K, V>>,
    /// The least recently used slot, or [`NIL`] when empty.
    head: usize,
    /// The most recently used slot, or [`NIL`] when empty.
    tail: usize,
    /// The bound. At least one: a map that can hold nothing cannot hand out
    /// a `&mut V`.
    capacity: usize,
}

impl<K: Hash + Eq + Clone, V> LruMap<K, V> {
    /// An empty map that will hold at most `capacity` entries, treating a
    /// capacity of zero as one.
    pub fn new(capacity: usize) -> Self {
        Self {
            index: HashMap::new(),
            entries: Vec::new(),
            head: NIL,
            tail: NIL,
            capacity: capacity.max(1),
        }
    }

    /// The bound this map holds itself to.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// How many entries the map holds.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the map holds nothing.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Whether `key` is present, without touching it.
    pub fn contains_key<Q>(&self, key: &Q) -> bool
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.index.contains_key(key)
    }

    /// The value for `key`, without touching it.
    pub fn peek<Q>(&self, key: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let slot = *self.index.get(key)?;
        Some(&self.entries[slot].value)
    }

    /// The value for `key`, which becomes the most recently used entry.
    pub fn get_mut<Q>(&mut self, key: &Q) -> Option<&mut V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let slot = *self.index.get(key)?;
        self.touch(slot);
        Some(&mut self.entries[slot].value)
    }

    /// The value for `key`, created with `make` if absent -- evicting the
    /// least recently used entry first when the map is full -- and in either
    /// case now the most recently used.
    pub fn get_or_insert_with(&mut self, key: K, make: impl FnOnce() -> V) -> &mut V {
        let slot = match self.index.get(&key) {
            Some(&slot) => {
                self.touch(slot);
                slot
            }
            None => self.admit(key, make()),
        };
        &mut self.entries[slot].value
    }

    /// Store `value` under `key` as the most recently used entry, evicting
    /// the least recently used one first when the key is new and the map is
    /// full. Returns the value the key held before, if any.
    pub fn insert(&mut self, key: K, value: V) -> Option<V> {
        if let Some(&slot) = self.index.get(&key) {
            self.touch(slot);
            return Some(std::mem::replace(&mut self.entries[slot].value, value));
        }
        self.admit(key, value);
        None
    }

    /// Remove `key`, returning its value if it was present.
    pub fn remove<Q>(&mut self, key: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let slot = *self.index.get(key)?;
        self.remove_slot(slot).map(|(_, value)| value)
    }

    /// Remove and return the least recently used entry.
    pub fn pop_lru(&mut self) -> Option<(K, V)> {
        if self.head == NIL {
            return None;
        }
        self.remove_slot(self.head)
    }

    /// Keep only the entries for which `keep` returns `true`, visiting them
    /// from least to most recently used and preserving that order among the
    /// survivors. Nothing is touched.
    pub fn retain(&mut self, mut keep: impl FnMut(&K, &mut V) -> bool) {
        let mut slot = self.head;
        while slot != NIL {
            let next = self.entries[slot].next;
            let entry = &mut self.entries[slot];
            if keep(&entry.key, &mut entry.value) {
                slot = next;
                continue;
            }
            // Removing swaps the last slot into this one. If `next` WAS the
            // last slot it now lives here, so the walk resumes at this slot.
            let last = self.entries.len() - 1;
            self.remove_slot(slot);
            slot = if next == last { slot } else { next };
        }
    }

    /// The entries from least to most recently used, without touching them.
    pub fn iter(&self) -> Iter<'_, K, V> {
        Iter {
            entries: &self.entries,
            slot: self.head,
        }
    }

    /// Every value, mutably, in no particular order and without touching.
    pub fn values_mut(&mut self) -> impl Iterator<Item = &mut V> {
        self.entries.iter_mut().map(|entry| &mut entry.value)
    }

    /// Make `slot` the most recently used entry.
    fn touch(&mut self, slot: usize) {
        if slot != self.tail {
            self.unlink(slot);
            self.link_tail(slot);
        }
    }

    /// Admit a key the map does not hold, evicting the least recently used
    /// entry first if the map is full, and return its slot.
    fn admit(&mut self, key: K, value: V) -> usize {
        if self.entries.len() >= self.capacity {
            self.pop_lru();
        }
        let slot = self.entries.len();
        self.entries.push(Entry {
            key: key.clone(),
            value,
            prev: NIL,
            next: NIL,
        });
        self.link_tail(slot);
        self.index.insert(key, slot);
        slot
    }

    /// Take `slot` out of the recency list, leaving its own links dangling.
    fn unlink(&mut self, slot: usize) {
        let (prev, next) = (self.entries[slot].prev, self.entries[slot].next);
        if prev == NIL {
            self.head = next;
        } else {
            self.entries[prev].next = next;
        }
        if next == NIL {
            self.tail = prev;
        } else {
            self.entries[next].prev = prev;
        }
    }

    /// Append `slot`, currently unlinked, at the most-recently-used end.
    fn link_tail(&mut self, slot: usize) {
        self.entries[slot].prev = self.tail;
        self.entries[slot].next = NIL;
        if self.tail == NIL {
            self.head = slot;
        } else {
            self.entries[self.tail].next = slot;
        }
        self.tail = slot;
    }

    /// Remove the entry in `slot` from the index, the list and the `Vec`,
    /// moving the last slot into its place so the `Vec` stays dense.
    fn remove_slot(&mut self, slot: usize) -> Option<(K, V)> {
        self.index.remove(&self.entries[slot].key);
        self.unlink(slot);
        let last = self.entries.len() - 1;
        if slot != last {
            self.entries.swap(slot, last);
            // The entry that lived in `last` now lives in `slot`: repoint its
            // neighbors, the list ends and its index entry.
            let (prev, next) = (self.entries[slot].prev, self.entries[slot].next);
            if prev == NIL {
                self.head = slot;
            } else {
                self.entries[prev].next = slot;
            }
            if next == NIL {
                self.tail = slot;
            } else {
                self.entries[next].prev = slot;
            }
            if let Some(index) = self.index.get_mut(&self.entries[slot].key) {
                *index = slot;
            }
        }
        self.entries.pop().map(|entry| (entry.key, entry.value))
    }
}

/// Walks an [`LruMap`] from least to most recently used.
pub struct Iter<'a, K, V> {
    /// The map's slots.
    entries: &'a [Entry<K, V>],
    /// The next slot to yield, or [`NIL`] when done.
    slot: usize,
}

impl<'a, K, V> Iterator for Iter<'a, K, V> {
    type Item = (&'a K, &'a V);

    fn next(&mut self) -> Option<Self::Item> {
        if self.slot == NIL {
            return None;
        }
        let entry = &self.entries[self.slot];
        self.slot = entry.next;
        Some((&entry.key, &entry.value))
    }
}

// ── Tests ────────────────────────────────────────────────────────────

/// Unit tests for the constant-time LRU map.
#[cfg(test)]
mod tests {
    use super::*;

    /// The keys from least to most recently used.
    fn order(map: &LruMap<u32, &'static str>) -> Vec<u32> {
        map.iter().map(|(k, _)| *k).collect()
    }

    /// Insertion order is recency order, and the first inserted is the
    /// first evicted when nothing has been touched since.
    #[test]
    fn the_first_inserted_is_evicted_first_when_nothing_is_touched() {
        let mut map = LruMap::new(3);
        for k in [1, 2, 3] {
            map.insert(k, "v");
        }
        assert_eq!(order(&map), vec![1, 2, 3]);
        map.insert(4, "v");
        assert_eq!(map.len(), 3, "the cap holds");
        assert_eq!(order(&map), vec![2, 3, 4], "1 was the least recently used");
    }

    /// A `get_mut` makes an entry the most recently used, so at the cap it
    /// is the untouched one that goes.
    #[test]
    fn a_touch_saves_an_entry_from_eviction() {
        let mut map = LruMap::new(3);
        for k in [1, 2, 3] {
            map.insert(k, "v");
        }
        assert!(map.get_mut(&1).is_some());
        assert_eq!(order(&map), vec![2, 3, 1]);
        map.insert(4, "v");
        assert_eq!(
            order(&map),
            vec![3, 1, 4],
            "2 was the least recently used once 1 had been touched"
        );
    }

    /// `peek` and `contains_key` read without touching.
    #[test]
    fn peek_and_contains_key_do_not_touch() {
        let mut map = LruMap::new(3);
        for k in [1, 2, 3] {
            map.insert(k, "v");
        }
        assert_eq!(map.peek(&1), Some(&"v"));
        assert!(map.contains_key(&1));
        assert_eq!(order(&map), vec![1, 2, 3], "reads must not reorder");
    }

    /// `insert` on a present key replaces the value, returns the old one,
    /// touches the entry and never evicts.
    #[test]
    fn insert_on_a_present_key_replaces_and_touches() {
        let mut map = LruMap::new(2);
        map.insert(1, "a");
        map.insert(2, "b");
        assert_eq!(map.insert(1, "c"), Some("a"));
        assert_eq!(map.len(), 2);
        assert_eq!(map.peek(&1), Some(&"c"));
        assert_eq!(order(&map), vec![2, 1]);
    }

    /// `get_or_insert_with` creates an absent key, evicting at the cap, and
    /// touches a present one without calling `make`.
    #[test]
    fn get_or_insert_with_creates_or_touches() {
        let mut map = LruMap::new(2);
        *map.get_or_insert_with(1, || 10) += 1;
        assert_eq!(map.peek(&1), Some(&11));
        map.get_or_insert_with(2, || 20);
        let touched = map.get_or_insert_with(1, || unreachable!("1 is present"));
        assert_eq!(*touched, 11);
        map.get_or_insert_with(3, || 30);
        assert_eq!(map.len(), 2, "the cap holds");
        assert!(map.contains_key(&1), "touched, so kept");
        assert!(!map.contains_key(&2), "the least recently used went");
        assert!(map.contains_key(&3));
    }

    /// Removing a slot in the middle keeps the order of the others, and the
    /// slot that was swapped into its place is still found by key.
    #[test]
    fn remove_keeps_order_and_the_swapped_slot_findable() {
        let mut map = LruMap::new(5);
        for k in [1, 2, 3, 4, 5] {
            map.insert(k, "v");
        }
        assert_eq!(map.remove(&2), Some("v"));
        assert_eq!(order(&map), vec![1, 3, 4, 5]);
        // 5 was the last slot and now occupies 2's old slot.
        assert!(map.get_mut(&5).is_some());
        assert_eq!(order(&map), vec![1, 3, 4, 5]);
        assert_eq!(map.remove(&5), Some("v"));
        assert_eq!(order(&map), vec![1, 3, 4]);
        assert_eq!(map.remove(&2), None, "already gone");
        assert_eq!(map.len(), 3);
    }

    /// Removing the head, the tail and the only entry all leave the list
    /// consistent.
    #[test]
    fn remove_at_the_ends_and_of_the_last_entry() {
        let mut map = LruMap::new(3);
        for k in [1, 2, 3] {
            map.insert(k, "v");
        }
        assert_eq!(map.pop_lru(), Some((1, "v")));
        assert_eq!(order(&map), vec![2, 3]);
        assert_eq!(map.remove(&3), Some("v"));
        assert_eq!(order(&map), vec![2]);
        assert_eq!(map.remove(&2), Some("v"));
        assert!(map.is_empty());
        assert_eq!(map.pop_lru(), None);
        map.insert(9, "v");
        assert_eq!(order(&map), vec![9], "usable again after emptying");
    }

    /// `retain` drops what the predicate rejects, keeps the order of the
    /// rest, and copes with the swap that removal performs mid-walk.
    #[test]
    fn retain_drops_rejected_entries_in_any_position() {
        for rejected in [
            vec![1],
            vec![6],
            vec![3, 4],
            vec![1, 6],
            vec![2, 5, 6],
            vec![1, 2, 3, 4, 5, 6],
        ] {
            let mut map = LruMap::new(6);
            for k in [1, 2, 3, 4, 5, 6] {
                map.insert(k, "v");
            }
            map.retain(|k, _| !rejected.contains(k));
            let expected: Vec<u32> = [1, 2, 3, 4, 5, 6]
                .into_iter()
                .filter(|k| !rejected.contains(k))
                .collect();
            assert_eq!(order(&map), expected, "rejecting {rejected:?}");
            assert_eq!(map.len(), expected.len());
            for k in &expected {
                assert!(map.contains_key(k), "{k} must still be indexed");
            }
            for k in &rejected {
                assert!(!map.contains_key(k), "{k} must be gone from the index");
            }
        }
    }

    /// A capacity of zero is treated as one, so `get_or_insert_with` can
    /// always hand back a value.
    #[test]
    fn zero_capacity_holds_one_entry() {
        let mut map = LruMap::new(0);
        assert_eq!(map.capacity(), 1);
        map.insert(1, "a");
        map.insert(2, "b");
        assert_eq!(order(&map), vec![2]);
    }

    /// The cost of admitting a key to a full map does not grow with the
    /// map. The same insertions at a cap of 16 and at a cap of 65,536, the
    /// minimum of five rounds each: constant-time eviction makes the two
    /// alike (measured at 1.0x), and a scan of the map to choose a victim
    /// makes the large one hundreds of times dearer.
    #[test]
    fn admitting_at_cap_costs_the_same_at_any_cap() {
        use std::time::{Duration, Instant};
        const INSERTS: u32 = 20_000;
        let cost_at = |capacity: usize| {
            let mut map: LruMap<u32, u32> = LruMap::new(capacity);
            for k in 0..capacity as u32 {
                map.insert(k, k);
            }
            let started = Instant::now();
            for k in 0..INSERTS {
                map.insert(1_000_000 + k, k);
            }
            let cost = started.elapsed();
            assert_eq!(map.len(), capacity, "control: the cap holds");
            cost
        };
        let mut small = Duration::MAX;
        let mut large = Duration::MAX;
        for _ in 0..5 {
            small = small.min(cost_at(16));
            large = large.min(cost_at(65_536));
        }
        let ratio = large.as_nanos() as f64 / small.as_nanos().max(1) as f64;
        assert!(
            ratio < 8.0,
            "admitting at a cap of 65,536 cost {ratio:.1}x admitting at a cap of 16 \
             ({large:?} against {small:?} for {INSERTS} inserts): eviction is \
             scanning the map"
        );
    }
}
