// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

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

/// One relay control datagram's cookie, which is how a retried command shows
/// on the wire (RP4).
///
/// A relay that keeps a reply cache answers a repeated cookie with the cached
/// reply, so a command sent twice under one cookie is a retry, not two
/// requests. The store counts these per control socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlCookie {
    /// The relay's control socket the datagram went to or came from.
    pub relay: std::net::SocketAddr,
    /// Which relay's protocol carried it.
    pub implementation: RelayImplementation,
    /// The cookie, as the datagram wrote it.
    pub cookie: String,
    /// `true` for a command to the relay, `false` for the relay's reply.
    pub command: bool,
}

/// Retry counts for one relay control socket, as a capture saw them (RP4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlChannelCounts {
    /// The relay's control socket.
    pub relay: std::net::SocketAddr,
    /// Which relay's protocol it speaks.
    pub implementation: RelayImplementation,
    /// Command datagrams seen, retries included.
    pub commands: u64,
    /// Commands that repeated a cookie already seen on this socket.
    pub retried_commands: u64,
    /// Of those, retries sent after the relay's answer to that cookie was
    /// already on the wire: the answer was lost or late on its way back to
    /// the proxy. The rest went out before any answer was seen.
    pub retried_after_answer: u64,
}

/// One socket's counts and the cookies it still remembers.
#[derive(Debug, Clone)]
struct Channel {
    /// What this socket's traffic has counted so far.
    counts: ControlChannelCounts,
    /// cookie -> whether an answer to it has been seen.
    seen: std::collections::HashMap<String, bool>,
    /// First-seen order, for forgetting the oldest past `capacity`.
    order: std::collections::VecDeque<String>,
}

/// Per-socket retry counting for relay control traffic (RP4).
///
/// A relay with a reply cache answers a repeated cookie with the cached
/// reply, so the same cookie on a second command is a retry. Remembers at most
/// `capacity` cookies per socket, oldest forgotten first, so a long capture
/// cannot grow it without bound; a retry of a forgotten cookie is not counted.
#[derive(Debug, Clone, Default)]
pub struct ControlChannels {
    /// Cookies remembered per socket before the oldest is forgotten.
    capacity: usize,
    /// One channel per relay control socket, in socket order.
    channels: std::collections::BTreeMap<std::net::SocketAddr, Channel>,
}

impl ControlChannels {
    /// Cookies remembered per control socket by [`Self::default_capacity`].
    pub const DEFAULT_CAPACITY: usize = 4096;

    /// An empty counter remembering at most `capacity` cookies per socket.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            channels: std::collections::BTreeMap::new(),
        }
    }

    /// An empty counter with [`Self::DEFAULT_CAPACITY`].
    #[must_use]
    pub fn default_capacity() -> Self {
        Self::new(Self::DEFAULT_CAPACITY)
    }

    /// Count one control datagram.
    pub fn record(&mut self, control: &ControlCookie) {
        let capacity = self.capacity.max(1);
        let channel = self
            .channels
            .entry(control.relay)
            .or_insert_with(|| Channel {
                counts: ControlChannelCounts {
                    relay: control.relay,
                    implementation: control.implementation,
                    commands: 0,
                    retried_commands: 0,
                    retried_after_answer: 0,
                },
                seen: std::collections::HashMap::new(),
                order: std::collections::VecDeque::new(),
            });
        if control.command {
            channel.counts.commands += 1;
            if let Some(answered) = channel.seen.get(&control.cookie) {
                channel.counts.retried_commands += 1;
                if *answered {
                    channel.counts.retried_after_answer += 1;
                }
            } else {
                channel.seen.insert(control.cookie.clone(), false);
                channel.order.push_back(control.cookie.clone());
                while channel.order.len() > capacity {
                    if let Some(old) = channel.order.pop_front() {
                        channel.seen.remove(&old);
                    }
                }
            }
        } else if let Some(answered) = channel.seen.get_mut(&control.cookie) {
            *answered = true;
        }
    }

    /// Add another counter's counts, socket by socket. Each worker of a
    /// `--cores` run sees a command and its retries together, since both
    /// travel between the same two hosts, so the counts add.
    pub fn merge(&mut self, other: ControlChannels) {
        for (relay, theirs) in other.channels {
            match self.channels.get_mut(&relay) {
                Some(mine) => {
                    mine.counts.commands += theirs.counts.commands;
                    mine.counts.retried_commands += theirs.counts.retried_commands;
                    mine.counts.retried_after_answer += theirs.counts.retried_after_answer;
                }
                None => {
                    self.channels.insert(relay, theirs);
                }
            }
        }
    }

    /// One row per control socket seen, in socket order.
    #[must_use]
    pub fn summary(&self) -> Vec<ControlChannelCounts> {
        self.channels.values().map(|c| c.counts.clone()).collect()
    }
}

#[cfg(test)]
mod control_channel_tests {
    use super::*;

    type TestError = Box<dyn std::error::Error>;

    fn relay() -> Result<std::net::SocketAddr, TestError> {
        Ok("192.0.2.40:7722".parse()?)
    }

    fn feed(channels: &mut ControlChannels, cookie: &str, command: bool) -> Result<(), TestError> {
        channels.record(&ControlCookie {
            relay: relay()?,
            implementation: RelayImplementation::Rtpproxy,
            cookie: cookie.to_string(),
            command,
        });
        Ok(())
    }

    /// A command answered and then sent again is one retry after an answer;
    /// one sent twice before any answer is a retry with none.
    #[test]
    fn retries_are_counted_and_told_apart_by_whether_the_answer_was_seen() -> Result<(), TestError>
    {
        let mut ch = ControlChannels::new(16);
        feed(&mut ch, "c1", true)?;
        feed(&mut ch, "c1", false)?;
        feed(&mut ch, "c1", true)?;
        feed(&mut ch, "c1", false)?;
        feed(&mut ch, "c2", true)?;
        feed(&mut ch, "c2", true)?;
        feed(&mut ch, "c2", false)?;
        feed(&mut ch, "c3", true)?;
        feed(&mut ch, "c3", false)?;
        let rows = ch.summary();
        assert_eq!(rows.len(), 1);
        let row = &rows[0];
        assert_eq!(row.relay, relay()?);
        assert_eq!(row.implementation, RelayImplementation::Rtpproxy);
        assert_eq!(row.commands, 5);
        assert_eq!(row.retried_commands, 2);
        assert_eq!(row.retried_after_answer, 1);
        Ok(())
    }

    /// Every repeat is a retry: a cookie sent three times is two retries.
    #[test]
    fn each_repeat_of_a_cookie_is_a_retry() -> Result<(), TestError> {
        let mut ch = ControlChannels::new(16);
        for _ in 0..3 {
            feed(&mut ch, "c1", true)?;
        }
        assert_eq!(ch.summary()[0].retried_commands, 2);
        Ok(())
    }

    /// A reply alone is not a command, and a reply with no command before it
    /// does not make a later first command a retry.
    #[test]
    fn replies_are_not_commands() -> Result<(), TestError> {
        let mut ch = ControlChannels::new(16);
        feed(&mut ch, "c1", false)?;
        feed(&mut ch, "c1", true)?;
        let row = &ch.summary()[0];
        assert_eq!(row.commands, 1);
        assert_eq!(row.retried_commands, 0);
        Ok(())
    }

    /// Memory is bounded: past `capacity` cookies the oldest is forgotten, so
    /// its repeat is no longer recognized. The bound is what keeps a busy
    /// control channel from growing the store without limit.
    #[test]
    fn the_cookie_memory_is_bounded() -> Result<(), TestError> {
        let mut ch = ControlChannels::new(2);
        feed(&mut ch, "a", true)?;
        feed(&mut ch, "b", true)?;
        feed(&mut ch, "c", true)?;
        feed(&mut ch, "a", true)?;
        assert_eq!(ch.summary()[0].retried_commands, 0, "a was forgotten");
        feed(&mut ch, "c", true)?;
        assert_eq!(ch.summary()[0].retried_commands, 1, "c was remembered");
        Ok(())
    }

    /// `--cores` merges the workers' counts by relay.
    #[test]
    fn merging_adds_counts_per_relay() -> Result<(), TestError> {
        let mut a = ControlChannels::new(16);
        feed(&mut a, "c1", true)?;
        feed(&mut a, "c1", true)?;
        feed(&mut a, "c1", false)?;
        let mut b = ControlChannels::new(16);
        feed(&mut b, "c2", true)?;
        feed(&mut b, "c2", false)?;
        feed(&mut b, "c2", true)?;
        a.merge(b);
        let row = &a.summary()[0];
        assert_eq!(row.commands, 4);
        assert_eq!(row.retried_commands, 2, "both workers' retries");
        assert_eq!(row.retried_after_answer, 1, "the second worker's");
        Ok(())
    }
}

/// Which relay engine received a control request, as sipnab saw it.
///
/// The two ways sipnab sees a request name the engine differently. A HEP copy
/// is sent by the engine itself and carries its `homer-id` as the HEP capture
/// id. A request captured on its way to the engine carries the address it was
/// sent to, which is the engine's `listen-ng` address. Neither is permission
/// to send anything: both come from captured traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum EngineIdentity {
    /// A HEP copy the engine sent: its `homer-id`, the HEP capture id.
    HomerId(u32),
    /// A request captured on its way to the engine: where it was sent.
    ListenNg(std::net::SocketAddr),
}

impl std::fmt::Display for EngineIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HomerId(id) => write!(f, "homer-id {id}"),
            Self::ListenNg(addr) => write!(f, "listen-ng {addr}"),
        }
    }
}

/// The two control requests that say which engine holds a call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EngineVerb {
    /// The proxy asked this engine to anchor the call's media.
    Offer,
    /// The proxy asked this engine to release the call.
    Delete,
}

/// One control request about a call that sipnab saw reach an engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineSighting {
    /// When the request was captured, or when the HEP copy says it was sent.
    pub at: chrono::DateTime<chrono::Utc>,
    /// The engine that received it.
    pub engine: EngineIdentity,
    /// What the request asked.
    pub verb: EngineVerb,
    /// For a HEP copy, the destination its address chunks name: the
    /// `listen-ng` address as the engine itself bound it, which is often a
    /// loopback address. Shown to help write a map row; never asked.
    pub reported_listen_ng: Option<std::net::SocketAddr>,
}

/// The engine sightings of each call, bounded.
///
/// Keeps at most `max_calls` Call-IDs, forgetting the one first seen longest
/// ago, and at most [`Self::PER_CALL`] sightings per call, forgetting the
/// oldest. A forgotten offer can no longer mark a call as moved, which is the
/// price of a bound a long capture cannot grow past.
#[derive(Debug, Clone, Default)]
pub struct EngineSightings {
    /// Call-IDs remembered before the first-seen one is forgotten.
    max_calls: usize,
    /// Each call's sightings, oldest first.
    calls: std::collections::HashMap<String, Vec<EngineSighting>>,
    /// First-seen order of the Call-IDs, for forgetting the oldest.
    order: std::collections::VecDeque<String>,
}

impl EngineSightings {
    /// Sightings kept per call.
    pub const PER_CALL: usize = 16;

    /// The most Call-IDs a dialog store's table keeps, whatever its dialog
    /// capacity: the table's memory stays bounded on a relay host, which sees
    /// ng traffic for calls whose SIP it never sees.
    pub const MAX_SIGHTING_CALLS: usize = 16_384;

    /// An empty table remembering at most `max_calls` calls.
    #[must_use]
    pub fn new(max_calls: usize) -> Self {
        Self {
            max_calls: max_calls.max(1),
            calls: std::collections::HashMap::new(),
            order: std::collections::VecDeque::new(),
        }
    }

    /// Remember one sighting for `call_id`.
    pub fn record(&mut self, call_id: &str, sighting: EngineSighting) {
        if let Some(seen) = self.calls.get_mut(call_id) {
            seen.push(sighting);
            if seen.len() > Self::PER_CALL {
                seen.remove(0);
            }
            return;
        }
        while self.calls.len() >= self.max_calls.max(1) {
            let Some(oldest) = self.order.pop_front() else {
                break;
            };
            self.calls.remove(&oldest);
        }
        self.order.push_back(call_id.to_string());
        self.calls.insert(call_id.to_string(), vec![sighting]);
    }

    /// The sightings of `call_id`, oldest first; empty for a call never seen.
    #[must_use]
    pub fn of(&self, call_id: &str) -> &[EngineSighting] {
        self.calls.get(call_id).map_or(&[], Vec::as_slice)
    }

    /// How many calls the table holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.calls.len()
    }

    /// Whether the table holds no call.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.calls.is_empty()
    }

    /// Add another table's sightings, call by call, in time order. Each
    /// worker of a `--cores` run sees some of a call's requests.
    pub fn merge(&mut self, other: EngineSightings) {
        let mut theirs = other.calls;
        for call_id in other.order {
            let Some(sightings) = theirs.remove(&call_id) else {
                continue;
            };
            let Some(mine) = self.calls.get_mut(&call_id) else {
                // A call only the other worker saw: admitted as a new call,
                // under this table's bound on calls.
                for s in sightings {
                    self.record(&call_id, s);
                }
                continue;
            };
            mine.extend(sightings);
            // Stable, so two sightings of one instant keep their order.
            mine.sort_by_key(|s| s.at);
            let excess = mine.len().saturating_sub(Self::PER_CALL);
            mine.drain(..excess);
        }
    }
}

#[cfg(test)]
mod engine_sighting_tests {
    use super::*;
    use chrono::TimeZone;

    type TestError = Box<dyn std::error::Error>;

    fn seen(secs: i64, id: u32, verb: EngineVerb) -> Result<EngineSighting, TestError> {
        Ok(EngineSighting {
            at: chrono::Utc
                .timestamp_opt(1_793_800_000 + secs, 0)
                .single()
                .ok_or("a fixed instant")?,
            engine: EngineIdentity::HomerId(id),
            verb,
            reported_listen_ng: None,
        })
    }

    /// A call's sightings come back oldest first, and another call's are
    /// kept apart.
    #[test]
    fn sightings_are_kept_per_call_in_order() -> Result<(), TestError> {
        let mut t = EngineSightings::new(8);
        t.record("a", seen(0, 2001, EngineVerb::Offer)?);
        t.record("b", seen(1, 2002, EngineVerb::Offer)?);
        t.record("a", seen(2, 2002, EngineVerb::Offer)?);
        assert_eq!(
            t.of("a"),
            [
                seen(0, 2001, EngineVerb::Offer)?,
                seen(2, 2002, EngineVerb::Offer)?
            ],
            "a call's sightings, oldest first"
        );
        assert_eq!(t.of("b").len(), 1, "another call's are kept apart");
        assert!(t.of("c").is_empty(), "a call never seen has none");
        Ok(())
    }

    /// At `max_calls`, the call seen first is forgotten; past `PER_CALL`, a
    /// call's oldest sighting is.
    #[test]
    fn the_table_is_bounded_by_calls_and_by_sightings_per_call() -> Result<(), TestError> {
        let mut t = EngineSightings::new(2);
        t.record("a", seen(0, 2001, EngineVerb::Offer)?);
        t.record("b", seen(1, 2001, EngineVerb::Offer)?);
        t.record("c", seen(2, 2001, EngineVerb::Offer)?);
        assert_eq!(t.len(), 2, "two calls at most");
        assert!(t.of("a").is_empty(), "the first-seen call is forgotten");
        assert_eq!(t.of("c").len(), 1, "the newest call is kept");
        let mut t = EngineSightings::new(2);
        let per_call = i64::try_from(EngineSightings::PER_CALL)?;
        for i in 0..=per_call {
            t.record("a", seen(i, 2001, EngineVerb::Offer)?);
        }
        assert_eq!(
            t.of("a").len(),
            EngineSightings::PER_CALL,
            "PER_CALL at most"
        );
        assert_eq!(
            t.of("a").first().map(|s| s.at),
            Some(seen(1, 2001, EngineVerb::Offer)?.at),
            "the oldest sighting is forgotten"
        );
        Ok(())
    }

    /// `--cores` merges each call's sightings in time order.
    #[test]
    fn merging_interleaves_a_calls_sightings_by_time() -> Result<(), TestError> {
        let mut a = EngineSightings::new(8);
        a.record("x", seen(0, 2001, EngineVerb::Offer)?);
        a.record("x", seen(4, 2001, EngineVerb::Delete)?);
        let mut b = EngineSightings::new(8);
        b.record("x", seen(2, 2002, EngineVerb::Offer)?);
        b.record("y", seen(3, 2002, EngineVerb::Offer)?);
        a.merge(b);
        let at: Vec<i64> = a
            .of("x")
            .iter()
            .map(|s| s.at.timestamp() - 1_793_800_000)
            .collect();
        assert_eq!(at, [0, 2, 4], "merging interleaves by time");
        assert_eq!(a.of("y").len(), 1, "a call only the other worker saw");
        Ok(())
    }

    /// A merge over `PER_CALL` keeps the newest sightings, whichever worker
    /// saw them.
    #[test]
    fn merging_past_the_per_call_bound_keeps_the_newest() -> Result<(), TestError> {
        let per_call = i64::try_from(EngineSightings::PER_CALL)?;
        let mut a = EngineSightings::new(8);
        for i in 0..per_call {
            a.record("x", seen(100 + i, 2001, EngineVerb::Offer)?);
        }
        let mut b = EngineSightings::new(8);
        b.record("x", seen(0, 2002, EngineVerb::Offer)?);
        a.merge(b);
        assert_eq!(a.of("x").len(), EngineSightings::PER_CALL, "still bounded");
        assert!(
            a.of("x")
                .iter()
                .all(|s| s.engine == EngineIdentity::HomerId(2001)),
            "the older sighting from the other worker is the one dropped"
        );
        Ok(())
    }

    /// The words every surface prints for an engine.
    #[test]
    fn an_engine_is_named_by_its_homer_id_or_its_listen_ng_address() -> Result<(), TestError> {
        assert_eq!(
            EngineIdentity::HomerId(2001).to_string(),
            "homer-id 2001",
            "a HEP copy's engine is named by its homer-id"
        );
        assert_eq!(
            EngineIdentity::ListenNg("192.0.2.5:2223".parse()?).to_string(),
            "listen-ng 192.0.2.5:2223",
            "a captured request's engine is named by where it was sent"
        );
        Ok(())
    }
}
