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
