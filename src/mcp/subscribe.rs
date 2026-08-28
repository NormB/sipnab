// SPDX-License-Identifier: MIT OR Apache-2.0

//! `resources/subscribe` and the change detection behind
//! `notifications/resources/updated` (PB4).
//!
//! An agent watching a live capture polls. `tail_dialogs` plus
//! `source_exhausted` is a loop that costs one model call per turn and learns
//! nothing on the turns where nothing happened. A subscription inverts that:
//! the client asks once and is told when the answer would be different.
//!
//! Three properties are load-bearing here, and each one exists because the
//! obvious implementation is wrong.
//!
//! # The state dies with the connection
//!
//! `SipnabMcp` is cloned once per MCP session (`transport.rs`), and every other
//! piece of shared state on it is an `Arc` *precisely so* the clones agree.
//! This one is the opposite: [`Subscriptions`] implements [`Clone`] by handing
//! back an EMPTY registry, because a clone is a new connection and a new
//! connection is not subscribed to anything. Sharing the registry would let one
//! agent's `resources/unsubscribe` silence another agent's subscription, and
//! would leave every departed session's entries behind with nothing able to
//! remove them.
//!
//! That also settles the lifecycle question a subscription registry usually
//! raises — what happens when a subscriber goes away without saying so. A
//! watcher holds a [`Watcher`], which is a WEAK handle. When the connection's
//! `SipnabMcp` is dropped the registry goes with it, the upgrade fails, and the
//! watcher reports [`Tick::Gone`] and stops. Nothing has to notice the
//! disconnect, because nothing is holding the connection open.
//!
//! # A notification means the content is different
//!
//! Not "a packet arrived", and not "the clock ticked". Detection is two
//! layered tests, cheap one first:
//!
//! 1. **The store generation.** `DialogStore::generation` is bumped by every
//!    mutation, so an unchanged generation PROVES an unchanged store, and the
//!    tick costs one `u64` read. An idle capture is free. RTP does not bump it
//!    — media moves the stream store — so a subscriber to a dialog list is not
//!    woken by audio the list does not show.
//! 2. **A digest of the rendered content.** A generation that moved is only a
//!    hint: `DialogStore::get_mut` bumps it on a MISS, and `compact_idle` bumps
//!    it unconditionally. So the rendered bytes are hashed and compared with
//!    what was last announced, and identical content sends nothing.
//!
//! The render only runs when step 1 says something moved, which is what makes
//! step 2 affordable. [`Watcher::tick`] takes the render as a closure so that
//! ordering is a property of the type rather than a convention a caller can
//! forget — and so a test can prove the closure was never called.
//!
//! # A burst is one notification
//!
//! A capture doing 200 calls a second mutates the dialog store thousands of
//! times a second. One notification per mutation is a denial of service
//! against the client, delivered politely. [`DEBOUNCE`] is the floor on the
//! interval between two notifications for one URI: changes inside the window
//! are held, not dropped, and the next tick past the window announces the
//! content as it then stands.

use std::collections::HashMap;
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

/// Shortest interval between two `notifications/resources/updated` for one URI.
///
/// **One second.** The notification carries no data — it says "read again" —
/// so its whole value is one `resources/read` round trip, through a model, on
/// the client's side. A shorter interval sends the second notification before
/// the client can have finished acting on the first, which is the storm
/// restated rather than avoided. A longer one would put the subscription
/// behind `tail_dialogs`, which an operator can already poll at a rate they
/// choose, and a feature slower than the loop it replaces is not worth the
/// state it costs.
///
/// It matches `progress::TICK` for the same underlying reason: one second is
/// the granularity at which a human or an agent can act on being told
/// something.
pub const DEBOUNCE: Duration = Duration::from_secs(1);

/// How often a watcher LOOKS, which is deliberately finer than [`DEBOUNCE`].
///
/// A tenth of the window, and the two numbers must not be equal. Sleeping the
/// whole window would make the SLEEP, rather than the debounce rule, the thing
/// enforcing the rate — and mutation testing showed exactly that: with a
/// one-second sleep, deleting the debounce check left every wire test green,
/// because the watcher could not look often enough to break the floor it was
/// no longer enforcing. A guarantee that holds only because of a sleep
/// somewhere else is not a guarantee, and it evaporates the day someone tunes
/// the sleep.
///
/// Looking ten times per window also puts the worst-case delay between a change
/// and its notification at one window plus one look rather than two windows.
/// The cost is ten wakeups per second per subscription, each one a read lock
/// and a `u64` compare that ends the tick on an idle capture — which is the
/// whole reason the cheap generation gate in [`Watcher::tick`] exists.
pub const POLL: Duration = Duration::from_millis(100);

/// Most resources one connection may subscribe to at once.
///
/// A cap for the reason `--mcp-max-concurrent` is one: each subscription is a
/// task waking once per [`POLL`] to read a `u64`, and an unbounded number of
/// them is unbounded work bought with one cheap request. Sixteen is well past
/// what an agent can reason about at once and far short of anything the
/// process would notice.
pub const MAX_SUBSCRIPTIONS: usize = 16;

/// 64-bit FNV-1a over `bytes`.
///
/// Written out rather than reached for because the requirement is narrow and
/// unusual: the value is compared only against another value produced by the
/// same process in the same run, so collision resistance does not matter and
/// determinism does. `DefaultHasher` would also work today and is documented
/// as unspecified across releases, which is a promise this needs and does not
/// have.
#[must_use]
pub fn digest(bytes: &[u8]) -> u64 {
    /// FNV-1a 64-bit offset basis.
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    /// FNV-1a 64-bit prime.
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut hash = OFFSET;
    for b in bytes {
        hash ^= u64::from(*b);
        hash = hash.wrapping_mul(PRIME);
    }
    hash
}

/// What one watcher tick concluded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tick {
    /// Nothing is subscribed to this URI any more — either the client
    /// unsubscribed or the connection is gone. The watcher must stop.
    Gone,
    /// The store has not been mutated since the last look, so the content
    /// cannot have changed and nothing was rendered.
    Unchanged,
    /// The store moved but the rendered content is byte-identical to what was
    /// last announced. Nothing is owed.
    SameContent,
    /// The content differs, and [`DEBOUNCE`] has not elapsed since the last
    /// notification. Held, not dropped: the next tick past the window sends it.
    Debounced,
    /// Send `notifications/resources/updated` for this URI now.
    Notify,
}

/// Why a `resources/subscribe` was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// This connection is already watching [`MAX_SUBSCRIPTIONS`] resources.
    TooMany {
        /// The ceiling that was reached.
        limit: usize,
    },
}

impl Refusal {
    /// A sentence naming what to change, addressed to the client.
    #[must_use]
    pub fn explain(&self) -> String {
        match self {
            Self::TooMany { limit } => format!(
                "this connection already holds the maximum of {limit} resource \
                 subscriptions; unsubscribe from one before subscribing to another"
            ),
        }
    }
}

/// What is remembered about one watched URI.
#[derive(Debug, Clone, Copy)]
struct Watched {
    /// Store revision at the last look. An unchanged value means the content
    /// cannot have changed, so nothing is rendered.
    generation: u64,
    /// Digest of the content the client was last told about.
    announced: u64,
    /// When that notification went out, or when the subscription was made.
    ///
    /// The window starts at subscribe rather than at the first change, so a
    /// burst that begins the instant a client subscribes is collapsed like any
    /// other burst.
    announced_at: Instant,
}

/// One connection's resource subscriptions.
///
/// Cheap to clone in the `Arc` sense internally, and deliberately NOT cheap in
/// the semantic sense: see the module docs and [`Subscriptions::clone`].
#[derive(Debug)]
pub struct Subscriptions {
    /// Watched URIs and their last-announced state.
    inner: Arc<parking_lot::Mutex<HashMap<String, Watched>>>,
}

impl Clone for Subscriptions {
    /// A NEW, EMPTY registry — this is not a copy, and that is the point.
    ///
    /// `SipnabMcp` is cloned once per MCP session, so cloning it means a new
    /// connection, and a new connection has subscribed to nothing. A derived
    /// `Clone` would share one `Arc` across every session on the server: one
    /// agent's `resources/unsubscribe` would silence another's subscription,
    /// and a session that ended without unsubscribing would leave entries
    /// nothing could ever remove.
    ///
    /// The same choice is what makes the disconnect lifecycle free. Each
    /// connection owns its registry outright, so when the connection's
    /// `SipnabMcp` drops, the registry drops, and every [`Watcher`] holding a
    /// weak handle to it reports [`Tick::Gone`] on its next tick.
    fn clone(&self) -> Self {
        Self::new()
    }
}

impl Default for Subscriptions {
    fn default() -> Self {
        Self::new()
    }
}

impl Subscriptions {
    /// A connection subscribed to nothing.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(parking_lot::Mutex::new(HashMap::new())),
        }
    }

    /// How many resources this connection is watching.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.lock().len()
    }

    /// Whether this connection is watching nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Whether `uri` is watched by this connection.
    #[must_use]
    pub fn contains(&self, uri: &str) -> bool {
        self.inner.lock().contains_key(uri)
    }

    /// Start watching `uri` from the state it is in right now.
    ///
    /// `generation` and `digest` describe the CURRENT content, so a
    /// subscription never fires for data the client could already have read at
    /// the moment it subscribed.
    ///
    /// Returns `true` when a watcher must be started, and `false` when this
    /// connection was already subscribed. MCP makes `resources/subscribe`
    /// idempotent, and this is what keeps that cheap.
    ///
    /// It is NOT what keeps the notification count right, and the difference
    /// is worth stating because the obvious reason is the wrong one. All the
    /// watchers for one URI share ONE map entry, so whichever ticks first
    /// records the digest and the rest see [`Tick::SameContent`] — removing
    /// this guard does not double anything a client receives. What it doubles
    /// is the WORK: one task per repeated subscribe, each waking every
    /// [`DEBOUNCE`] and each rendering the resource, for the lifetime of the
    /// connection. A client that re-subscribes in a loop would accumulate them
    /// without ever seeing a symptom. Mutation testing found this: deleting
    /// the guard left every wire test green, and only
    /// `a_repeated_subscribe_does_not_start_a_second_watcher` went red.
    ///
    /// # Errors
    ///
    /// [`Refusal::TooMany`] past [`MAX_SUBSCRIPTIONS`]. Re-subscribing to a
    /// URI already held is never refused, because it adds nothing to count.
    pub fn add(
        &self,
        uri: &str,
        generation: u64,
        digest: u64,
        now: Instant,
    ) -> Result<bool, Refusal> {
        let mut held = self.inner.lock();
        if held.contains_key(uri) {
            return Ok(false);
        }
        if held.len() >= MAX_SUBSCRIPTIONS {
            return Err(Refusal::TooMany {
                limit: MAX_SUBSCRIPTIONS,
            });
        }
        held.insert(
            uri.to_string(),
            Watched {
                generation,
                announced: digest,
                announced_at: now,
            },
        );
        Ok(true)
    }

    /// Stop watching `uri`. Returns whether it was being watched.
    ///
    /// The removal IS the cancellation: a watcher checks membership before it
    /// sends, so a URI no longer in the map cannot produce another
    /// notification.
    pub fn remove(&self, uri: &str) -> bool {
        self.inner.lock().remove(uri).is_some()
    }

    /// A non-owning handle for the task that watches `uri`.
    ///
    /// Weak on purpose: the watcher must not keep a departed connection's
    /// registry alive. See the module docs.
    #[must_use]
    pub fn watcher(&self, uri: &str) -> Watcher {
        Watcher {
            inner: Arc::downgrade(&self.inner),
            uri: uri.to_string(),
        }
    }
}

/// One watcher task's non-owning view of the subscription it serves.
#[derive(Debug, Clone)]
pub struct Watcher {
    /// Weak handle to the connection's registry. A failed upgrade means the
    /// connection is gone.
    inner: Weak<parking_lot::Mutex<HashMap<String, Watched>>>,
    /// The URI this watcher serves.
    uri: String,
}

impl Watcher {
    /// The URI this watcher serves.
    #[must_use]
    pub fn uri(&self) -> &str {
        &self.uri
    }

    /// Decide what this tick owes the client, recording the decision.
    ///
    /// `generation` is the cheap test — an unchanged store cannot have changed
    /// content — and `render` is only called when it moved. That ordering is
    /// the whole cost model of this feature, so it is enforced by the
    /// signature: a caller cannot render first by accident.
    ///
    /// On [`Tick::Notify`] the new digest and `now` are recorded, which is what
    /// opens the next [`DEBOUNCE`] window. On [`Tick::Debounced`] NOTHING is
    /// recorded — not even the generation — so the held change is retried on
    /// the next tick rather than lost.
    ///
    /// # What the lock covers, and the straggler it does not prevent
    ///
    /// The registry lock is held across `render` on purpose: checking
    /// membership, rendering, and recording the decision have to be one step,
    /// or an `unsubscribe` landing between the check and the record would be
    /// overwritten. The cost is that a concurrent subscribe or unsubscribe on
    /// the SAME connection waits out one render, which is bounded by
    /// `--mcp-max-rows` and is less work than any `list_dialogs` call.
    ///
    /// What it does not prevent: an `unsubscribe` arriving after this returned
    /// [`Tick::Notify`] and before the caller has sent the notification. The
    /// client then receives one straggler for a subscription it has canceled.
    /// That is inherent to a message already on its way rather than a race
    /// worth locking against, and MCP has no rule a late notification breaks.
    pub fn tick(&self, generation: u64, now: Instant, render: impl FnOnce() -> u64) -> Tick {
        let Some(inner) = self.inner.upgrade() else {
            return Tick::Gone;
        };
        let mut held = inner.lock();
        let Some(state) = held.get_mut(&self.uri) else {
            return Tick::Gone;
        };
        if state.generation == generation {
            return Tick::Unchanged;
        }
        let digest = render();
        if digest == state.announced {
            // The store moved and the answer did not: `get_mut` bumps the
            // generation on a miss, and `compact_idle` bumps it whether or not
            // it evicted anything. Record the generation so the same
            // non-change is not rendered twice.
            state.generation = generation;
            return Tick::SameContent;
        }
        if now.duration_since(state.announced_at) < DEBOUNCE {
            return Tick::Debounced;
        }
        state.generation = generation;
        state.announced = digest;
        state.announced_at = now;
        Tick::Notify
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A digest that ignores its input would make every change invisible.
    #[test]
    fn different_bytes_digest_differently() {
        assert_ne!(digest(b"one dialog"), digest(b"two dialogs"));
        assert_eq!(
            digest(b"one dialog"),
            digest(b"one dialog"),
            "the same bytes must digest the same, or every tick notifies"
        );
    }

    /// An empty input still produces the basis rather than zero, so "no
    /// content" and "not yet rendered" cannot be confused.
    #[test]
    fn an_empty_render_is_not_the_zero_digest() {
        assert_ne!(digest(b""), 0);
    }

    /// A fresh connection watches nothing.
    #[test]
    fn a_new_registry_is_empty() {
        assert!(Subscriptions::new().is_empty());
    }

    /// Cloning is a new connection, not a copy of this one.
    ///
    /// The failure this guards is the derived `Clone`: with it, every HTTP
    /// session on the server shares one registry, so one agent's unsubscribe
    /// silences another's subscription.
    #[test]
    fn a_clone_starts_with_no_subscriptions() {
        let subs = Subscriptions::new();
        subs.add("sipnab://live/dialogs", 1, 7, Instant::now())
            .expect("first subscription fits");
        assert_eq!(subs.len(), 1);

        let other = subs.clone();
        assert!(
            other.is_empty(),
            "a clone is a NEW connection; sharing the registry would let one \
             session unsubscribe another"
        );
        assert_eq!(subs.len(), 1, "and cloning must not disturb the original");
    }

    /// Removing from a clone cannot reach the original's subscription.
    #[test]
    fn one_connection_cannot_unsubscribe_another() {
        let a = Subscriptions::new();
        a.add("sipnab://live/dialogs", 1, 7, Instant::now())
            .expect("subscribe");
        let b = a.clone();
        assert!(!b.remove("sipnab://live/dialogs"));
        assert!(
            a.contains("sipnab://live/dialogs"),
            "session B removed session A's subscription"
        );
    }

    /// Subscribing twice to one URI is idempotent and starts one watcher.
    #[test]
    fn a_repeated_subscribe_does_not_start_a_second_watcher() {
        let subs = Subscriptions::new();
        let t = Instant::now();
        assert_eq!(subs.add("sipnab://live/dialogs", 1, 7, t), Ok(true));
        assert_eq!(
            subs.add("sipnab://live/dialogs", 1, 7, t),
            Ok(false),
            "each repeat would spawn another task waking every DEBOUNCE and \
             rendering the resource, for the life of the connection, with \
             nothing a client could observe to reveal it"
        );
        assert_eq!(subs.len(), 1);
    }

    /// The per-connection ceiling is enforced.
    #[test]
    fn the_subscription_ceiling_refuses_the_next_uri() {
        let subs = Subscriptions::new();
        let t = Instant::now();
        for i in 0..MAX_SUBSCRIPTIONS {
            subs.add(&format!("sipnab://live/dialogs/{i}"), 1, 7, t)
                .expect("inside the ceiling");
        }
        assert_eq!(
            subs.add("sipnab://live/dialogs/one-too-many", 1, 7, t),
            Err(Refusal::TooMany {
                limit: MAX_SUBSCRIPTIONS
            }),
            "an uncapped registry is unbounded work bought with one cheap request"
        );
    }

    /// An unchanged generation costs nothing: the render is never called.
    ///
    /// This is the cost model of the whole feature. Without it an idle capture
    /// re-renders and re-hashes its dialog list once a second per subscriber,
    /// forever, to conclude nothing happened.
    #[test]
    fn an_unchanged_store_is_never_rendered() {
        let subs = Subscriptions::new();
        let t = Instant::now();
        subs.add("sipnab://live/dialogs", 9, 7, t)
            .expect("subscribe");
        let mut rendered = false;
        let tick = subs.watcher("sipnab://live/dialogs").tick(9, t, || {
            rendered = true;
            7
        });
        assert_eq!(tick, Tick::Unchanged);
        assert!(
            !rendered,
            "the render ran on an untouched store; the cheap gate is not gating"
        );
    }

    /// A generation that moved without changing the answer sends nothing.
    #[test]
    fn a_generation_bump_with_identical_content_sends_nothing() {
        let subs = Subscriptions::new();
        let t = Instant::now();
        subs.add("sipnab://live/dialogs", 9, 7, t)
            .expect("subscribe");
        assert_eq!(
            subs.watcher("sipnab://live/dialogs")
                .tick(10, t + DEBOUNCE * 2, || 7),
            Tick::SameContent,
            "DialogStore::get_mut bumps the generation on a MISS; notifying on \
             that would wake a client for nothing"
        );
    }

    /// A real change, past the window, notifies exactly once.
    #[test]
    fn a_change_past_the_window_notifies_once() {
        let subs = Subscriptions::new();
        let t = Instant::now();
        subs.add("sipnab://live/dialogs", 9, 7, t)
            .expect("subscribe");
        let w = subs.watcher("sipnab://live/dialogs");
        let later = t + DEBOUNCE + Duration::from_millis(1);
        assert_eq!(w.tick(10, later, || 42), Tick::Notify);
        assert_eq!(
            w.tick(10, later + Duration::from_millis(1), || 42),
            Tick::Unchanged,
            "the same change must not be announced twice"
        );
    }

    /// A burst inside one window is ONE notification, and nothing is lost.
    #[test]
    fn a_burst_inside_the_window_collapses_to_one_notification() {
        let subs = Subscriptions::new();
        let t = Instant::now();
        subs.add("sipnab://live/dialogs", 0, 7, t)
            .expect("subscribe");
        let w = subs.watcher("sipnab://live/dialogs");

        // Twenty mutations inside one second, each with different content.
        let mut notifications = 0;
        for i in 1..=20_u64 {
            let at = t + Duration::from_millis(i * 40);
            if w.tick(i, at, || 1000 + i) == Tick::Notify {
                notifications += 1;
            }
        }
        assert_eq!(
            notifications, 0,
            "every change inside the first window must be held"
        );

        // Past the window the accumulated change is announced, once.
        let past = t + DEBOUNCE + Duration::from_millis(1);
        assert_eq!(w.tick(21, past, || 9999), Tick::Notify);
        assert_eq!(
            w.tick(21, past + Duration::from_millis(1), || 9999),
            Tick::Unchanged,
            "the burst must produce one notification, not one per mutation"
        );
    }

    /// A debounced change is HELD, not dropped.
    ///
    /// The distinction is the whole difference between a debounce and a
    /// sampler: a dropped change means a client that is told nothing happened
    /// when something did.
    #[test]
    fn a_debounced_change_is_retried_rather_than_lost() {
        let subs = Subscriptions::new();
        let t = Instant::now();
        subs.add("sipnab://live/dialogs", 1, 7, t)
            .expect("subscribe");
        let w = subs.watcher("sipnab://live/dialogs");
        assert_eq!(
            w.tick(2, t + Duration::from_millis(10), || 42),
            Tick::Debounced
        );
        assert_eq!(
            w.tick(2, t + DEBOUNCE + Duration::from_millis(10), || 42),
            Tick::Notify,
            "a change suppressed by the window must still reach the client"
        );
    }

    /// After `unsubscribe`, a change produces nothing at all.
    #[test]
    fn an_unsubscribed_uri_notifies_nothing() {
        let subs = Subscriptions::new();
        let t = Instant::now();
        subs.add("sipnab://live/dialogs", 1, 7, t)
            .expect("subscribe");
        let w = subs.watcher("sipnab://live/dialogs");
        assert!(subs.remove("sipnab://live/dialogs"));
        assert_eq!(
            w.tick(2, t + DEBOUNCE * 5, || 42),
            Tick::Gone,
            "an unsubscribed URI must not produce another notification"
        );
    }

    /// Unsubscribing something that was never subscribed says so.
    #[test]
    fn removing_an_unwatched_uri_reports_false() {
        assert!(!Subscriptions::new().remove("sipnab://live/dialogs"));
    }

    /// A watcher whose connection is gone stops, with nobody telling it.
    ///
    /// This is the lifecycle answer to "a subscriber went away without saying
    /// so": the registry is owned by the connection, so dropping the
    /// connection drops the registry and every watcher sees it.
    #[test]
    fn a_watcher_stops_when_its_connection_is_dropped() {
        let subs = Subscriptions::new();
        let t = Instant::now();
        subs.add("sipnab://live/dialogs", 1, 7, t)
            .expect("subscribe");
        let w = subs.watcher("sipnab://live/dialogs");
        drop(subs);
        assert_eq!(
            w.tick(2, t + DEBOUNCE * 5, || 42),
            Tick::Gone,
            "a watcher must not outlive the connection that asked for it"
        );
    }

    /// The watcher knows which URI it serves, so the notification names it.
    #[test]
    fn a_watcher_carries_its_uri() {
        let subs = Subscriptions::new();
        assert_eq!(
            subs.watcher("sipnab://live/dialogs").uri(),
            "sipnab://live/dialogs"
        );
    }

    /// The refusal names the ceiling rather than saying "no".
    #[test]
    fn the_refusal_names_the_ceiling() {
        let text = Refusal::TooMany { limit: 16 }.explain();
        assert!(text.contains("16"), "{text}");
        assert!(text.contains("unsubscribe"), "{text}");
    }
}
