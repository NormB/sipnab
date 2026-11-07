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
    /// The frame the request was read from, which places it in the run's
    /// read order: a `--cores` merge puts the workers' sightings back in that
    /// order. `None` for one not read from a frame.
    pub frame: Option<crate::capture::packet::FrameRef>,
}

/// The engine sightings of each call, bounded by how many it holds.
///
/// Holds the last [`Self::window`]-many sightings read, of any call, and of
/// each call the last [`Self::PER_CALL`] of those. Each sighting past the
/// window forgets the one read longest ago, and a call none of whose
/// sightings is left is forgotten. A forgotten offer can no longer mark a call
/// as moved, which is the price of a bound a long capture cannot grow past.
///
/// # Why the bound counts sightings, not calls
///
/// A `--cores N` run records each sighting on the worker that owns its host
/// pair, and one call's requests to two engines are on two pairs. The merged
/// table must be the one `--cores 1` builds, and each worker can only bound
/// its own table. A bound on sightings read is one every worker can keep:
/// a sighting among the last W the run read is among the last W its worker
/// read, so the workers' windows together hold the run's window, and
/// [`Self::merge`] rebuilds it exactly. A bound on calls is not: a worker
/// that forgets a call because it saw many other calls cannot know that
/// another worker's requests for that call, or for the calls it saw, kept it
/// in the run's table. Through 0.5.236 the table kept 16,384 Call-IDs, first
/// seen first forgotten, and a `--cores` merge kept other calls than
/// `--cores 1` did.
#[derive(Debug, Clone, Default)]
pub struct EngineSightings {
    /// Sightings held before the one read longest ago is forgotten.
    window: usize,
    /// Every sighting in the window, read longest ago first, with its call.
    seen: std::collections::VecDeque<(std::sync::Arc<str>, EngineSighting)>,
    /// How many sightings were forgotten: the number of the first in `seen`,
    /// counting every sighting this table recorded from 0.
    forgotten: u64,
    /// Each call's last [`Self::PER_CALL`] sightings in the window, by
    /// number, read longest ago first.
    calls: std::collections::HashMap<std::sync::Arc<str>, std::collections::VecDeque<u64>>,
}

impl EngineSightings {
    /// Sightings kept per call.
    pub const PER_CALL: usize = 16;

    /// Sightings a dialog store's table holds per dialog its capacity
    /// allows: an `offer` and a `delete`, and two more for a call that moves
    /// or is offered again.
    pub const PER_DIALOG: usize = 4;

    /// The most sightings a dialog store's table holds, whatever its dialog
    /// capacity: the table's memory stays bounded on a relay host, which sees
    /// ng traffic for calls whose SIP it never sees.
    pub const MAX_SIGHTINGS: usize = 65_536;

    /// An empty table holding at most `window` sightings (at least one).
    #[must_use]
    pub fn new(window: usize) -> Self {
        Self {
            window: window.max(1),
            seen: std::collections::VecDeque::new(),
            forgotten: 0,
            calls: std::collections::HashMap::new(),
        }
    }

    /// The table of a dialog store holding at most `max_dialogs` dialogs:
    /// [`Self::PER_DIALOG`] sightings per dialog, at most
    /// [`Self::MAX_SIGHTINGS`].
    #[must_use]
    pub fn for_dialogs(max_dialogs: usize) -> Self {
        Self::new(
            max_dialogs
                .max(1)
                .saturating_mul(Self::PER_DIALOG)
                .min(Self::MAX_SIGHTINGS),
        )
    }

    /// How many sightings the table holds before it forgets one.
    #[must_use]
    pub fn window(&self) -> usize {
        self.window
    }

    /// Remember one sighting for `call_id`, read after every one before it.
    pub fn record(&mut self, call_id: &str, sighting: EngineSighting) {
        let call = self.calls.get_key_value(call_id).map_or_else(
            || std::sync::Arc::from(call_id),
            |(c, _)| std::sync::Arc::clone(c),
        );
        self.record_call(call, sighting);
    }

    /// [`Self::record`] for a call already named by a shared string.
    fn record_call(&mut self, call: std::sync::Arc<str>, sighting: EngineSighting) {
        let number = self.forgotten + self.seen.len() as u64;
        let kept = self.calls.entry(std::sync::Arc::clone(&call)).or_default();
        kept.push_back(number);
        if kept.len() > Self::PER_CALL {
            kept.pop_front();
        }
        self.seen.push_back((call, sighting));
        while self.seen.len() > self.window.max(1) {
            self.forget_oldest();
        }
    }

    /// Forget the sighting read longest ago, and its call when it was that
    /// call's last.
    fn forget_oldest(&mut self) {
        let Some((call, _)) = self.seen.pop_front() else {
            return;
        };
        let number = self.forgotten;
        self.forgotten += 1;
        if let Some(kept) = self.calls.get_mut(&call) {
            // A call holding more than `PER_CALL` sightings in the window
            // kept only its last ones, so its oldest is not among them.
            if kept.front() == Some(&number) {
                kept.pop_front();
            }
            if kept.is_empty() {
                self.calls.remove(&call);
            }
        }
    }

    /// The sightings of `call_id` in the order they were read; empty for a
    /// call the table does not hold.
    #[must_use]
    pub fn of(&self, call_id: &str) -> Vec<EngineSighting> {
        let Some(kept) = self.calls.get(call_id) else {
            return Vec::new();
        };
        kept.iter()
            .filter_map(|&number| {
                let index = usize::try_from(number.checked_sub(self.forgotten)?).ok()?;
                self.seen.get(index).map(|(_, s)| s.clone())
            })
            .collect()
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

    /// Add the sightings of `others`, the tables of a `--cores` run's
    /// workers, as one table fed every sighting in read order holds them.
    ///
    /// Each worker of a `--cores` run sees some of a call's requests, each in
    /// the order the run read them. The tables' sightings, this table's
    /// included, are put back in the run's read order and recorded again
    /// under this table's window, so the order of a call's sightings, which
    /// ones past [`Self::PER_CALL`] are kept and which calls past the window
    /// are kept are the ones `--cores 1` keeps.
    ///
    /// # Arguments
    ///
    /// * `others` — The tables to fold in (consumed). Each must have been fed
    ///   its sightings in read order and hold a window at least this table's,
    ///   as every worker of one run does: then the tables together hold the
    ///   run's last `window` sightings.
    /// * `read_position` — Where a sighting sits in the run's read order.
    ///   Sightings of one position keep the order of the tables (this one
    ///   first) and, within a table, the order it read them in.
    pub fn merge<K: Ord>(
        &mut self,
        others: impl IntoIterator<Item = EngineSightings>,
        read_position: impl Fn(&EngineSighting) -> K,
    ) {
        let mut all: Vec<(std::sync::Arc<str>, EngineSighting)> =
            std::mem::take(&mut self.seen).into();
        for other in others {
            all.extend(other.seen);
        }
        // Stable, so one position keeps the tables' order and each table's.
        all.sort_by_cached_key(|(_, s)| read_position(s));
        *self = Self::new(self.window);
        for (call, sighting) in all {
            self.record_call(call, sighting);
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
            frame: None,
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

    /// Sighting `ordinal` of a run's read order: `secs` in, at engine `id`.
    fn read(
        ordinal: u64,
        secs: i64,
        id: u32,
        verb: EngineVerb,
    ) -> Result<EngineSighting, TestError> {
        let mut s = seen(secs, id, verb)?;
        s.frame = Some(
            crate::capture::packet::FrameLocator {
                source: "read-order.pcap",
                origin: crate::capture::packet::FrameOrigin {
                    ordinal,
                    digest: None,
                    verifiable: true,
                },
            }
            .to_frame_ref(),
        );
        Ok(s)
    }

    /// Where a test sighting sits in its run's read order.
    fn position(s: &EngineSighting) -> Option<u64> {
        s.frame.as_ref().map(|f| f.origin.ordinal)
    }

    /// Everything a table answers for `calls`: how many calls it holds, and
    /// each call's sightings.
    fn answers(t: &EngineSightings, calls: &[&str]) -> (usize, Vec<Vec<EngineSighting>>) {
        (t.len(), calls.iter().map(|c| t.of(c)).collect())
    }

    /// The window holds the sightings read last, of whatever call: each new
    /// one past it forgets the one read longest ago, and a call none of whose
    /// sightings is left is forgotten.
    #[test]
    fn the_window_holds_the_last_sightings_read_of_any_call() -> Result<(), TestError> {
        let mut t = EngineSightings::new(3);
        t.record("a", read(0, 0, 2001, EngineVerb::Offer)?);
        t.record("a", read(1, 1, 2001, EngineVerb::Offer)?);
        t.record("b", read(2, 2, 2001, EngineVerb::Offer)?);
        t.record("a", read(3, 3, 2001, EngineVerb::Delete)?);
        let ordinals = |t: &EngineSightings, c: &str| -> Vec<Option<u64>> {
            t.of(c).iter().map(position).collect()
        };
        assert_eq!(
            ordinals(&t, "a"),
            [Some(1), Some(3)],
            "the first read is forgotten"
        );
        t.record("c", read(4, 4, 2001, EngineVerb::Offer)?);
        t.record("d", read(5, 5, 2001, EngineVerb::Offer)?);
        assert_eq!(ordinals(&t, "a"), [Some(3)], "and the next");
        assert!(
            t.of("b").is_empty(),
            "a call with no sighting left is forgotten"
        );
        assert_eq!(t.len(), 3, "a, c and d");
        Ok(())
    }

    /// Past `PER_CALL`, a call keeps the sightings read last, whatever
    /// their timestamps say.
    #[test]
    fn past_per_call_a_call_keeps_the_sightings_read_last() -> Result<(), TestError> {
        let mut t = EngineSightings::new(100);
        let per_call = u64::try_from(EngineSightings::PER_CALL)?;
        for i in 0..=per_call {
            let secs = 100 - i64::try_from(i)?;
            t.record("a", read(i, secs, 2001, EngineVerb::Offer)?);
        }
        let kept: Vec<Option<u64>> = t.of("a").iter().map(position).collect();
        let expected: Vec<Option<u64>> = (1..=per_call).map(Some).collect();
        assert_eq!(kept, expected, "the first read is forgotten, in read order");
        Ok(())
    }

    /// A dialog store's table holds `PER_DIALOG` sightings per dialog its
    /// capacity allows, and never more than `MAX_SIGHTINGS`.
    #[test]
    fn a_table_for_dialogs_holds_per_dialog_sightings_up_to_the_maximum() -> Result<(), TestError> {
        let fill = |t: &mut EngineSightings, n: usize| -> Result<(), TestError> {
            for i in 0..n {
                t.record(&format!("c{i}"), seen(0, 2001, EngineVerb::Offer)?);
            }
            Ok(())
        };
        let mut t = EngineSightings::for_dialogs(2);
        fill(&mut t, 3 * EngineSightings::PER_DIALOG)?;
        assert_eq!(
            t.len(),
            2 * EngineSightings::PER_DIALOG,
            "two dialogs' worth"
        );
        let mut t = EngineSightings::for_dialogs(0);
        fill(&mut t, 3 * EngineSightings::PER_DIALOG)?;
        assert_eq!(
            t.len(),
            EngineSightings::PER_DIALOG,
            "at least one dialog's worth"
        );
        let mut t = EngineSightings::for_dialogs(usize::MAX);
        fill(&mut t, EngineSightings::MAX_SIGHTINGS + 1)?;
        assert_eq!(
            t.len(),
            EngineSightings::MAX_SIGHTINGS,
            "never more than the maximum"
        );
        Ok(())
    }

    /// Merge `tables` into an empty table and, separately, into the first
    /// of them, and check both against `single`.
    fn assert_merges_to(
        single: &EngineSightings,
        tables: &[EngineSightings],
        calls: &[&str],
        what: &str,
    ) {
        let window = single.window;
        let mut fresh = EngineSightings::new(window);
        fresh.merge(tables.to_vec(), position);
        assert_eq!(
            answers(&fresh, calls),
            answers(single, calls),
            "{what}, into an empty table"
        );
        let mut rest = tables.to_vec();
        let mut first = rest.remove(0);
        first.merge(rest, position);
        assert_eq!(
            answers(&first, calls),
            answers(single, calls),
            "{what}, into the first table"
        );
    }

    /// A `--cores` merge equals one table fed every sighting in read order,
    /// for every assignment of the sightings to one, two or three workers,
    /// merged in either order: the ties in time keep their read order, and
    /// the window forgets the same sightings.
    #[test]
    fn a_merge_equals_one_table_fed_every_sighting_in_read_order() -> Result<(), TestError> {
        let script: [(&str, i64, u32, EngineVerb); 8] = [
            ("a", 5, 2001, EngineVerb::Offer),
            ("b", 5, 2002, EngineVerb::Offer),
            ("a", 5, 2002, EngineVerb::Offer),
            ("c", 1, 2001, EngineVerb::Offer),
            ("a", 2, 2003, EngineVerb::Delete),
            ("b", 0, 2001, EngineVerb::Offer),
            ("d", 9, 2002, EngineVerb::Offer),
            ("a", 9, 2001, EngineVerb::Offer),
        ];
        let calls = ["a", "b", "c", "d"];
        let sightings = script
            .iter()
            .zip(0..)
            .map(|(&(call, secs, id, verb), n)| Ok((call, read(n, secs, id, verb)?)))
            .collect::<Result<Vec<_>, TestError>>()?;
        let mut cases = 0;
        for window in [3, 100] {
            let mut single = EngineSightings::new(window);
            for (call, s) in &sightings {
                single.record(call, s.clone());
            }
            for workers in 1..=3u32 {
                for assignment in 0..workers.pow(8) {
                    let mut tables = vec![EngineSightings::new(window); workers as usize];
                    let mut rest = assignment;
                    for (call, s) in &sightings {
                        tables[(rest % workers) as usize].record(call, s.clone());
                        rest /= workers;
                    }
                    let what =
                        format!("window {window}, {workers} workers, assignment {assignment}");
                    assert_merges_to(&single, &tables, &calls, &what);
                    tables.reverse();
                    assert_merges_to(&single, &tables, &calls, &format!("{what}, reversed"));
                    cases += 1;
                }
            }
        }
        assert_eq!(cases, 2 * (1 + 256 + 6561), "every assignment was merged");
        Ok(())
    }

    /// Sightings of one read position (here, none read from a frame) keep
    /// the order of the tables, the merging one first, and within a table
    /// the order it read them in.
    #[test]
    fn one_read_position_keeps_the_tables_order_and_each_tables_own() -> Result<(), TestError> {
        let mut a = EngineSightings::new(8);
        a.record("x", seen(2, 2001, EngineVerb::Offer)?);
        a.record("x", seen(1, 2002, EngineVerb::Offer)?);
        let mut b = EngineSightings::new(8);
        b.record("x", seen(0, 2003, EngineVerb::Offer)?);
        b.record("x", seen(3, 2004, EngineVerb::Offer)?);
        let engines = |t: &EngineSightings| -> Vec<EngineIdentity> {
            t.of("x").iter().map(|s| s.engine).collect()
        };
        let mut forward = a.clone();
        forward.merge([b.clone()], position);
        assert_eq!(
            engines(&forward),
            [2001, 2002, 2003, 2004].map(EngineIdentity::HomerId),
            "the merging table's first, each in its own order"
        );
        let mut backward = b;
        backward.merge([a], position);
        assert_eq!(
            engines(&backward),
            [2003, 2004, 2001, 2002].map(EngineIdentity::HomerId),
            "the merging table's first, each in its own order"
        );
        Ok(())
    }

    /// Which of `workers` workers reads sighting `n`.
    type WorkerOf = fn(u64, u64) -> u64;

    /// Past `PER_CALL`, a merge keeps the sightings `--cores 1` keeps, the
    /// ones read last, however the workers split the call.
    #[test]
    fn a_merge_past_per_call_keeps_the_sightings_read_last() -> Result<(), TestError> {
        let per_call = u64::try_from(EngineSightings::PER_CALL)?;
        let total = per_call + 4;
        let sightings = (0..total)
            .map(|n| {
                // Read later, timed earlier: the timestamps run backwards
                // through the second half.
                let secs = if n < total / 2 {
                    100 + i64::try_from(n)?
                } else {
                    i64::try_from(n)?
                };
                read(n, secs, 2001 + u32::try_from(n % 3)?, EngineVerb::Offer)
            })
            .collect::<Result<Vec<_>, TestError>>()?;
        let mut single = EngineSightings::new(1000);
        for s in &sightings {
            single.record("x", s.clone());
        }
        let splits: [(&str, WorkerOf); 3] = [
            ("alternating", |n, w| n % w),
            ("in halves", |n, w| n * w / 20),
            ("strided", |n, w| (n * 7) % w),
        ];
        for workers in 2..=3u64 {
            for (name, worker_of) in splits {
                let mut tables = vec![EngineSightings::new(1000); usize::try_from(workers)?];
                for (n, s) in (0..).zip(&sightings) {
                    tables[usize::try_from(worker_of(n, workers))?].record("x", s.clone());
                }
                let what = format!("{workers} workers, {name}");
                assert_merges_to(&single, &tables, &["x"], &what);
                tables.reverse();
                assert_merges_to(&single, &tables, &["x"], &format!("{what}, reversed"));
            }
        }
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
