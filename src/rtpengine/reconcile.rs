// SPDX-License-Identifier: MIT OR Apache-2.0

//! The two moments sipnab asks a relay anything (RE4).
//!
//! A passive decoder cannot name a call whose offer happened before it
//! started, and incident response usually begins mid-call. Asking the relay
//! closes that gap. Asking it repeatedly turns an analysis tool into a service
//! that talks to production, so this module exists to hold the line between
//! the two.
//!
//! # The bounds, and how each one is held
//!
//! - **Never periodic.** There is no timer, no thread and no interval in this
//!   module. It acts when it is called, and it is called from exactly two
//!   places: once at startup, and when a stream turns up that no signaling
//!   explains. A poller cannot be built out of these pieces by accident --
//!   it would have to be written on purpose, somewhere else.
//! - **Once per question.** Startup latches. Each relay-side port is asked
//!   about at most once for the life of the run, so a stream that stays
//!   unexplained -- which is the normal case for traffic the relay is not
//!   handling at all -- does not re-ask on every packet.
//! - **A ceiling that does not depend on the traffic.** [`DEFAULT_BUDGET`],
//!   or whatever [`Reconciler::with_budget`] was given, bounds transactions
//!   for the whole run. A capture full of orphans cannot
//!   turn into a flood of control traffic, and when the ceiling is reached
//!   sipnab SAYS so rather than quietly attributing nothing.
//! - **Read-only, in the type system.** [`ReadOnlyRelay`] has two methods.
//!   There is no path from this module to `delete` or `start recording`,
//!   because there is no method that means them.
//!
//! # Why the index is built at startup
//!
//! `list` names the calls; only `query` says which relay-side PORT belongs to
//! which call, and the port is the one thing sipnab can already see. So
//! startup spends `list` plus one `query` per call and keeps the port index.
//! After that, most unexplained streams are answered from memory for free.
//!
//! A stream that is STILL unexplained after that lookup means something the
//! snapshot did not contain -- typically a call the relay set up after sipnab
//! started. That, and only that, is the second trigger.

#[cfg(all(not(target_arch = "wasm32"), feature = "native"))]
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

#[cfg(all(not(target_arch = "wasm32"), feature = "native"))]
use super::control::{CallView, ControlReply};
#[cfg(all(not(target_arch = "wasm32"), feature = "native"))]
use crate::security::transmit_guard::TransmitPermit;

/// Everything the reconciler is permitted to ask a relay.
///
/// Two methods. rtpengine's ng protocol also carries `offer`, `answer`,
/// `delete` and `start recording`, every one of which CHANGES a production
/// relay. None of them is reachable from here, and adding one would mean
/// adding a method to this trait -- a visible act in a diff rather than an
/// oversight in a call site.
#[cfg(all(not(target_arch = "wasm32"), feature = "native"))]
pub trait ReadOnlyRelay {
    /// Ask which calls are up.
    ///
    /// # Errors
    ///
    /// When the relay cannot be reached or its answer does not parse.
    fn list(&self, permit: &TransmitPermit, limit: u32) -> anyhow::Result<ControlReply>;

    /// Ask about one call.
    ///
    /// # Errors
    ///
    /// When the relay cannot be reached or its answer does not parse.
    fn query(&self, permit: &TransmitPermit, call_id: &str) -> anyhow::Result<ControlReply>;

    /// Where this relay is, for messages an operator reads.
    fn describe(&self) -> String;
}

/// What the relay knows about one relay-side port.
///
/// This is the answer an unexplained stream was missing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attribution {
    /// The relay's own address for this port.
    ///
    /// Carried because the port alone does not identify a socket: rtpengine
    /// allocates from one port range across every `--interface`, so the same
    /// port number genuinely appears on two addresses at once. Keying on the
    /// port alone would attribute one interface's media to the other's call.
    pub local_address: IpAddr,
    /// The call this port belongs to.
    pub call_id: String,
    /// The side of the call holding it.
    pub tag: String,
    /// The other side(s).
    pub peer_tags: Vec<String>,
    /// Whether the relay holds this port for RTCP rather than RTP.
    pub is_rtcp: bool,
    /// The codec the relay recorded for this side, where it recorded one.
    pub codec: Option<String>,
}

/// Why a lookup came back with nothing.
///
/// "No attribution" and "could not ask" are different facts, and collapsing
/// them is how a run that never reached the relay comes to look like a run
/// that asked and was told the stream belongs to nobody.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unattributed {
    /// The relay was asked and does not hold this port.
    ///
    /// A real answer: the stream is not this relay's.
    RelayDoesNotHoldIt,
    /// The snapshot was partial, so the port may belong to a call that was
    /// never enumerated.
    EnumerationWasPartial,
    /// The transaction ceiling was reached, so this port was never asked about.
    BudgetSpent,
    /// The relay named calls, but some of them could not be read, so this
    /// port may belong to one of those.
    SnapshotIncomplete {
        /// How many calls the relay named but sipnab could not read.
        unread_calls: usize,
    },
    /// The relay could not be reached, refused the question, or its answer
    /// did not parse.
    AskFailed {
        /// What went wrong, for an operator to read.
        reason: String,
    },
}

impl Unattributed {
    /// One line saying what actually happened, in the operator's terms.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::RelayDoesNotHoldIt => "the relay was asked and does not hold this port, so this \
                 stream is not its media"
                .to_owned(),
            Self::EnumerationWasPartial => {
                "the relay returned a PARTIAL list of calls, so this port may \
                 belong to a call that was never enumerated -- this is not \
                 evidence the stream is unattached"
                    .to_owned()
            }
            Self::BudgetSpent => "the control-transaction ceiling for this run was reached, so \
                 this port was never asked about"
                .to_owned(),
            Self::SnapshotIncomplete { unread_calls } => {
                format!(
                    "the relay named {unread_calls} call(s) that could not be \
                     read, so this port may belong to one of them -- this is \
                     not evidence the stream is unattached"
                )
            }
            Self::AskFailed { reason } => {
                format!(
                    "the relay could not be asked ({reason}), so nothing is known about this port"
                )
            }
        }
    }
}

/// How many Call-IDs to ask `list` for.
///
/// rtpengine's own default, and it warns that raising it may exceed a UDP
/// datagram. [`super::control::Enumeration::truncated`] is what keeps a capped answer from
/// reading as a complete one.
pub const DEFAULT_LIST_LIMIT: u32 = 32;

/// Control transactions one run may spend, in total.
///
/// Enough for a full startup snapshot (one `list` plus a `query` per call at
/// the default limit) and a comparable refresh afterwards. The point is that
/// the ceiling does not depend on how much traffic the capture carries: a
/// capture full of orphans cannot turn into a flood of control traffic.
pub const DEFAULT_BUDGET: u32 = 2 * (DEFAULT_LIST_LIMIT + 1);

/// Asks a relay at the two moments RE4 allows, and never otherwise.
#[cfg(all(not(target_arch = "wasm32"), feature = "native"))]
pub struct Reconciler<R: ReadOnlyRelay> {
    /// The relay, reachable only through the two read-only questions.
    relay: R,
    /// Startup fires once. There is no second startup.
    startup_done: bool,
    /// Relay-side socket to what the relay said about it.
    ///
    /// `(IpAddr, u16)` and not `u16`, matching the key
    /// [`crate::rtp::stream_store::StreamStore`] uses for SDP endpoints. The
    /// two indexes are joined on this key, so they have to agree on what a
    /// socket is.
    index: HashMap<(IpAddr, u16), Attribution>,
    /// Calls already queried, so a refresh asks only about new ones.
    known_calls: HashSet<String>,
    /// Sockets already asked about, so an unexplained stream is asked about
    /// once rather than once per packet.
    asked_ports: HashSet<(IpAddr, u16)>,
    /// Relay streams whose address the relay reported in a form that is not
    /// an IP address, and which therefore could not be keyed.
    ///
    /// Counted rather than dropped: a port sipnab cannot key is a port it
    /// will never attribute, and that is a gap the summary has to name.
    unkeyable_streams: usize,
    /// Whether the last enumeration was capped.
    enumeration_partial: bool,
    /// Why the last enumeration could not be read, when it could not be.
    ///
    /// Held as STATE rather than only reported in the summary line, because
    /// the summary is prose an operator reads and this is the answer a caller
    /// gets back. If only the prose says the relay was unreachable, the
    /// caller's answer is still "not held" -- which is the collapse this
    /// whole type exists to prevent.
    last_ask_failure: Option<String>,
    /// Sockets learned since the last [`Reconciler::take_new_links`].
    ///
    /// Only the NEW ones may be handed back. Re-registering an endpoint the
    /// relay reported at startup would stamp it with the current time, and
    /// the store's expiry clock measures from when the relay SAID it -- so
    /// replaying the whole index would make every endpoint look perpetually
    /// fresh and quietly disable the staleness bound.
    new_since_take: Vec<(IpAddr, u16)>,
    /// Calls the relay named that sipnab could not read.
    ///
    /// A set rather than a count because a refresh must be able to CLEAR one
    /// that later succeeded, and a counter cannot say which.
    unread_calls: HashSet<String>,
    /// Transactions spent so far this run.
    spent: u32,
    /// The ceiling on [`Self::spent`], fixed for the run and independent of
    /// how much traffic the capture carries.
    budget: u32,
    /// How many Call-IDs to enumerate.
    list_limit: u32,
}

#[cfg(all(not(target_arch = "wasm32"), feature = "native"))]
impl<R: ReadOnlyRelay> Reconciler<R> {
    /// Point a reconciler at a relay.
    #[must_use]
    pub fn new(relay: R) -> Self {
        Self {
            relay,
            startup_done: false,
            index: HashMap::new(),
            known_calls: HashSet::new(),
            asked_ports: HashSet::new(),
            unkeyable_streams: 0,
            enumeration_partial: false,
            last_ask_failure: None,
            new_since_take: Vec::new(),
            unread_calls: HashSet::new(),
            spent: 0,
            budget: DEFAULT_BUDGET,
            list_limit: DEFAULT_LIST_LIMIT,
        }
    }

    /// Override the transaction ceiling.
    #[must_use]
    pub fn with_budget(mut self, budget: u32) -> Self {
        self.budget = budget;
        self
    }

    /// Override how many Call-IDs to enumerate.
    #[must_use]
    pub fn with_list_limit(mut self, limit: u32) -> Self {
        self.list_limit = limit;
        self
    }

    /// Control transactions this run has spent.
    ///
    /// Exposed because "is this a poller?" is a question about a NUMBER, and
    /// a test that cannot read the number cannot answer it.
    #[must_use]
    pub fn transactions(&self) -> u32 {
        self.spent
    }

    /// Where the relay is, for messages an operator reads.
    #[must_use]
    pub fn describe_relay(&self) -> String {
        self.relay.describe()
    }

    /// The transaction ceiling for this run.
    ///
    /// Exposed beside [`Self::transactions`] so a report can state both --
    /// "8 of 66" says whether the run was bounded by the relay or by sipnab.
    #[must_use]
    pub fn budget(&self) -> u32 {
        self.budget
    }

    /// Ports the relay accounted for.
    #[must_use]
    pub fn attributed_ports(&self) -> usize {
        self.index.len()
    }

    /// Whether the relay's last enumeration was capped.
    #[must_use]
    pub fn enumeration_was_partial(&self) -> bool {
        self.enumeration_partial
    }

    /// Every socket the relay accounted for, as `(address, port, call-id)`.
    ///
    /// The startup snapshot's whole product. Registering these as media
    /// endpoints is what lets a stream that appears LATER be attributed
    /// without asking the relay again -- which is why the packet path never
    /// has to make a network call.
    pub fn links(&self) -> impl Iterator<Item = (IpAddr, u16, &str)> {
        self.index
            .iter()
            .map(|((addr, port), a)| (*addr, *port, a.call_id.as_str()))
    }

    /// The snapshot as owned links, to carry into the capture path.
    ///
    /// Taken once and carried as data because each live mode builds its OWN
    /// stream store, in a different file: the reconciler is not shared across
    /// them, and a snapshot that reached one and not the other would attribute
    /// a call in the TUI and leave it an orphan headless.
    ///
    /// # Arguments
    ///
    /// * `taken_at` — when the relay answered, which becomes the start of the
    ///   endpoint's expiry clock in the stream store.
    #[must_use]
    pub fn snapshot(&self, taken_at: chrono::DateTime<chrono::Utc>) -> RelaySnapshot {
        RelaySnapshot {
            links: self
                .links()
                .map(|(address, port, call_id)| RelayLink {
                    address,
                    port,
                    call_id: call_id.to_owned(),
                })
                .collect(),
            taken_at: Some(taken_at),
        }
    }

    /// Take only what the relay has said SINCE the last call.
    ///
    /// The startup snapshot is applied once; everything a later refresh
    /// learns is applied as it is learned, stamped with the moment the relay
    /// answered. Handing back the whole index instead would re-stamp every
    /// startup endpoint with a fresh time and quietly disable the store's
    /// staleness bound on all of them.
    #[must_use]
    pub fn take_new_links(&mut self, taken_at: chrono::DateTime<chrono::Utc>) -> RelaySnapshot {
        let links: Vec<RelayLink> = self
            .new_since_take
            .drain(..)
            .filter_map(|socket| {
                self.index.get(&socket).map(|a| RelayLink {
                    address: socket.0,
                    port: socket.1,
                    call_id: a.call_id.clone(),
                })
            })
            .collect();
        RelaySnapshot {
            taken_at: (!links.is_empty()).then_some(taken_at),
            links,
        }
    }

    /// Spend one transaction, or refuse.
    fn spend(&mut self) -> bool {
        if self.spent >= self.budget {
            return false;
        }
        self.spent += 1;
        true
    }

    /// FIRST TRIGGER: build the port index once, at startup.
    ///
    /// Returns a line for the operator, or `None` when nothing was asked
    /// because startup had already run.
    ///
    /// # Errors
    ///
    /// Never. A relay that cannot be reached is reported in the returned
    /// summary, because a capture is still worth reading when the relay is
    /// down, and failing the run over an enrichment would be the wrong trade.
    pub fn at_startup(&mut self, permit: &TransmitPermit) -> Option<String> {
        if self.startup_done {
            return None;
        }
        self.startup_done = true;
        Some(self.refresh(permit))
    }

    /// SECOND TRIGGER: a stream nothing explains.
    ///
    /// Answers from the startup snapshot where it can. Only a port the
    /// snapshot did not contain refreshes it, and only the first time that
    /// port is seen -- so a stream that stays unexplained costs one lookup for
    /// the run, not one per packet.
    pub fn on_unexplained_stream(
        &mut self,
        permit: &TransmitPermit,
        local_address: IpAddr,
        local_port: u16,
    ) -> Result<Attribution, Unattributed> {
        let socket = (local_address, local_port);
        if let Some(found) = self.index.get(&socket) {
            return Ok(found.clone());
        }
        if !self.asked_ports.insert(socket) {
            // Already asked about this port and the refresh did not find it.
            // Asking again would produce the same answer and one more packet.
            return Err(self.why_not(socket));
        }
        // The snapshot did not contain it, so the snapshot is stale: a call
        // the relay set up after sipnab started. Refresh, asking only about
        // calls not already known.
        let _ = self.refresh(permit);
        self.index
            .get(&socket)
            .cloned()
            .ok_or_else(|| self.why_not(socket))
    }

    /// Which of the several reasons "nothing" means, for this port.
    ///
    /// Ordered most-conclusive-first, and [`Unattributed::RelayDoesNotHoldIt`]
    /// is reachable ONLY when a complete answer was actually read. Every
    /// other arm is a gap in what sipnab knows, and reporting a gap as a
    /// relay's denial is the specific lie this ordering prevents.
    ///
    /// Where both kinds of gap hold, the truncated enumeration is named
    /// first: it is the wider one -- calls that were never even listed --
    /// and the operator's fix for it (raise the limit, or ask over TCP) also
    /// shrinks the other.
    fn why_not(&self, _socket: (IpAddr, u16)) -> Unattributed {
        if let Some(reason) = &self.last_ask_failure {
            Unattributed::AskFailed {
                reason: reason.clone(),
            }
        } else if self.spent >= self.budget {
            Unattributed::BudgetSpent
        } else if self.enumeration_partial {
            Unattributed::EnumerationWasPartial
        } else if !self.unread_calls.is_empty() {
            Unattributed::SnapshotIncomplete {
                unread_calls: self.unread_calls.len(),
            }
        } else {
            Unattributed::RelayDoesNotHoldIt
        }
    }

    /// Enumerate, then query every call not already indexed.
    fn refresh(&mut self, permit: &TransmitPermit) -> String {
        if !self.spend() {
            return format!(
                "rtpengine at {}: not asked -- {}",
                self.relay.describe(),
                Unattributed::BudgetSpent.describe()
            );
        }
        let enumeration = match self.relay.list(permit, self.list_limit) {
            Ok(ControlReply::Calls(e)) => e,
            Ok(ControlReply::Refused { reason }) => {
                self.last_ask_failure = Some(format!("the relay refused: {reason}"));
                return format!(
                    "rtpengine at {} refused to enumerate its calls: {reason}",
                    self.relay.describe()
                );
            }
            Ok(other) => {
                self.last_ask_failure =
                    Some("the relay answered a `list` with something else".to_owned());
                return format!(
                    "rtpengine at {} answered a `list` with something else ({other:?})",
                    self.relay.describe()
                );
            }
            Err(e) => {
                self.last_ask_failure = Some(format!("{e:#}"));
                return format!(
                    "rtpengine at {} could not be asked which calls are up: {e:#}",
                    self.relay.describe()
                );
            }
        };
        // The relay answered. Whatever went wrong last time no longer governs.
        self.last_ask_failure = None;
        self.enumeration_partial = enumeration.truncated;

        let mut queried = 0_usize;
        for call_id in &enumeration.call_ids {
            // Membership, not insertion: a call counts as known once it has
            // been READ. A call whose query failed stays unknown, so the next
            // refresh retries it rather than writing it off for the run --
            // and the budget is what bounds that, not a one-shot latch.
            if self.known_calls.contains(call_id) {
                continue;
            }
            if !self.spend() {
                break;
            }
            queried += 1;
            match self.relay.query(permit, call_id) {
                Ok(ControlReply::Call(view)) => {
                    self.absorb(&view);
                    self.known_calls.insert(call_id.clone());
                    self.unread_calls.remove(call_id);
                }
                Ok(_) | Err(_) => {
                    self.unread_calls.insert(call_id.clone());
                }
            }
        }
        let failed = self.unread_calls.len();

        let mut line = format!(
            "rtpengine at {}: {}; queried {queried} of them, {} relay port(s) \
             now attributable",
            self.relay.describe(),
            enumeration.describe(),
            self.index.len()
        );
        if failed > 0 {
            line.push_str(&format!(
                ". {failed} call(s) could not be read, so their ports stay \
                 unattributed -- that is a gap in this snapshot, not evidence \
                 those streams are unattached"
            ));
        }
        if self.unkeyable_streams > 0 {
            line.push_str(&format!(
                ". {} relay stream(s) reported an address that is not an IP \
                 address and could not be keyed, so their ports stay \
                 unattributed",
                self.unkeyable_streams
            ));
        }
        if self.spent >= self.budget {
            line.push_str(
                ". The control-transaction ceiling for this run is now spent, \
                 so no further questions will be asked",
            );
        }
        line
    }

    /// Fold one call's view into the port index.
    fn absorb(&mut self, view: &CallView) {
        for tag in &view.tags {
            for stream in &tag.streams {
                let Ok(addr) = stream.local_address.parse::<IpAddr>() else {
                    // The relay named a socket sipnab cannot key. Counted, so
                    // the summary can say the snapshot is short by this much,
                    // rather than the port quietly never being attributed.
                    self.unkeyable_streams += 1;
                    continue;
                };
                let socket = (addr, stream.local_port);
                let previous = self.index.insert(
                    socket,
                    Attribution {
                        local_address: addr,
                        call_id: view.call_id.clone(),
                        tag: tag.tag.clone(),
                        peer_tags: tag.in_dialogue_with.clone(),
                        is_rtcp: stream.is_rtcp,
                        codec: tag.codec.clone(),
                    },
                );
                // Reported when the socket is new OR when the relay has handed
                // it to a DIFFERENT call. A port pool recycles: call A ends,
                // its port is freed, and call B is given it. Reporting only
                // the first insert left the store holding A's endpoint while
                // this index held B's, so media on that port was credited to
                // a call that had ended -- attributed to the WRONG call, not
                // merely unattributed.
                //
                // Keyed on the call and nothing else, because the call is all
                // a [`RelayLink`] carries. A socket whose call is unchanged is
                // not news, and re-reporting one would re-date the endpoint:
                // the store expires an endpoint 300 s after the relay SAID it,
                // so a socket re-stamped on every refresh never goes stale and
                // that bound quietly stops existing.
                if previous.is_none_or(|p| p.call_id != view.call_id)
                    && !self.new_since_take.contains(&socket)
                {
                    self.new_since_take.push(socket);
                }
            }
        }
    }
}

/// One relay-side socket the control plane attributed to a call.
///
/// The startup snapshot, flattened into the shape the capture path registers.
/// A struct rather than a tuple because it travels through config into four
/// separate stream stores, and `(addr, port, call_id)` read at the far end is
/// three unlabelled fields whose order is a guess.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayLink {
    /// The relay's own address for this socket.
    pub address: IpAddr,
    /// The relay's own port.
    pub port: u16,
    /// The call the relay says holds it.
    pub call_id: String,
}

/// Sockets the hand-off queue holds before it starts refusing.
///
/// A CHOICE sized to absorb a burst while the reconciler is mid-transaction,
/// not a measurement. The capture path never waits on it: a full queue drops
/// and counts, because stalling packet processing on a relay round trip is
/// the trade RE4 exists to avoid.
pub const ORPHAN_QUEUE_DEPTH: usize = 1024;

/// Where the capture path offers a stream nothing explains.
///
/// Non-blocking by construction. There is no `send` that waits: the only way
/// to hand a socket over cannot block the thread that found it, however long
/// the relay takes to answer.
pub struct OrphanSink {
    /// The hand-off. Bounded, so a stalled reconciler cannot grow it.
    tx: std::sync::mpsc::SyncSender<(IpAddr, u16)>,
    /// Sockets the queue had no room for.
    dropped: std::sync::atomic::AtomicU64,
}

impl OrphanSink {
    /// Offer one socket, or count that it could not be offered.
    pub fn offer(&self, address: IpAddr, port: u16) {
        if self.tx.try_send((address, port)).is_err() {
            self.dropped
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }

    /// Sockets never offered because the queue was full, or the reconciler
    /// had already stopped.
    ///
    /// Non-zero means this run asked about fewer unexplained streams than it
    /// saw. That has to be SAID: a stream never offered is not a stream the
    /// relay disowned.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.dropped.load(std::sync::atomic::Ordering::Relaxed)
    }
}

/// Build a hand-off pair: the sink the capture path offers to, and the
/// receiver the reconciler drains.
///
/// The receiver ends its loop when every sink is dropped, which is how the
/// run stops the reconciler without a flag to poll or a timeout to pick.
#[must_use]
pub fn orphan_channel() -> (OrphanSink, std::sync::mpsc::Receiver<(IpAddr, u16)>) {
    let (tx, rx) = std::sync::mpsc::sync_channel(ORPHAN_QUEUE_DEPTH);
    (
        OrphanSink {
            tx,
            dropped: std::sync::atomic::AtomicU64::new(0),
        },
        rx,
    )
}

/// A relay's startup snapshot, and when it was taken.
///
/// The time is carried rather than re-derived where the snapshot is applied.
/// [`crate::rtp::stream_store`] expires an endpoint 300 s after it was learned
/// before letting it name a NEW stream, and that clock has to start when the
/// relay ANSWERED -- not when whichever store happened to be built. Two live
/// modes build their stores in two different files, and `Utc::now()` in each
/// of them is two different answers to "when did the relay say this".
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RelaySnapshot {
    /// Every socket the relay accounted for.
    pub links: Vec<RelayLink>,
    /// When the relay answered. `None` when it was never asked.
    pub taken_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// The live client is the only production implementation.
///
/// The impl lives here rather than beside [`super::control::ControlClient`]
/// so that the
/// direction of the dependency matches the layering: reconciliation knows
/// about the wire, and the wire knows nothing about reconciliation.
#[cfg(all(not(target_arch = "wasm32"), feature = "native"))]
impl ReadOnlyRelay for super::control::ControlClient {
    fn list(&self, permit: &TransmitPermit, limit: u32) -> anyhow::Result<ControlReply> {
        Self::list(self, permit, limit)
    }

    fn query(&self, permit: &TransmitPermit, call_id: &str) -> anyhow::Result<ControlReply> {
        Self::query(self, permit, call_id)
    }

    fn describe(&self) -> String {
        self.addr().to_string()
    }
}

#[cfg(test)]
#[cfg(all(not(target_arch = "wasm32"), feature = "native"))]
mod tests {
    use super::*;
    use crate::capture::CaptureSource;
    use crate::rtpengine::control::{Enumeration, RelayStream, RelayTag};
    use std::cell::RefCell;

    /// The address the scripted relay reports for every stream.
    const RELAY_IP: &str = "203.0.113.7";

    /// That same address, parsed, for building lookup keys.
    fn relay_ip() -> std::net::IpAddr {
        RELAY_IP.parse().expect("a literal v4 address parses")
    }

    /// A permit, which only a live source can grant.
    fn permit() -> TransmitPermit {
        let live = CaptureSource::Live {
            device: "eth0".to_owned(),
        };
        TransmitPermit::for_source(&live).expect("a live source grants a permit")
    }

    /// What a scripted relay should answer with.
    enum Answer {
        Calls(Vec<&'static str>, bool),
        Refuse(&'static str),
        Fail,
    }

    /// A relay that answers from a script and counts what it was asked.
    struct ScriptedRelay {
        list_answer: Answer,
        /// Ports to hand back per Call-ID, or `None` to fail the query.
        calls: HashMap<String, Option<Vec<u16>>>,
        /// The interface address a call's ports live on, when not the default.
        addresses: HashMap<String, String>,
        /// Fail every query until this many have been attempted.
        fail_first: u32,
        lists: RefCell<u32>,
        queries: RefCell<Vec<String>>,
    }

    impl ScriptedRelay {
        fn new(list_answer: Answer) -> Self {
            Self {
                list_answer,
                calls: HashMap::new(),
                addresses: HashMap::new(),
                fail_first: 0,
                lists: RefCell::new(0),
                queries: RefCell::new(Vec::new()),
            }
        }

        fn holding(mut self, call_id: &str, ports: Option<Vec<u16>>) -> Self {
            self.calls.insert(call_id.to_owned(), ports);
            self
        }

        fn holding_on(mut self, call_id: &str, addr: &str, ports: Vec<u16>) -> Self {
            self.calls.insert(call_id.to_owned(), Some(ports));
            self.addresses.insert(call_id.to_owned(), addr.to_owned());
            self
        }

        fn failing_first(mut self, n: u32) -> Self {
            self.fail_first = n;
            self
        }
    }

    impl ReadOnlyRelay for ScriptedRelay {
        fn list(&self, _permit: &TransmitPermit, _limit: u32) -> anyhow::Result<ControlReply> {
            *self.lists.borrow_mut() += 1;
            match &self.list_answer {
                Answer::Calls(ids, truncated) => Ok(ControlReply::Calls(Enumeration {
                    call_ids: ids.iter().map(|s| (*s).to_owned()).collect(),
                    truncated: *truncated,
                })),
                Answer::Refuse(reason) => Ok(ControlReply::Refused {
                    reason: (*reason).to_owned(),
                }),
                Answer::Fail => anyhow::bail!("connection refused"),
            }
        }

        fn query(&self, _permit: &TransmitPermit, call_id: &str) -> anyhow::Result<ControlReply> {
            self.queries.borrow_mut().push(call_id.to_owned());
            if (self.queries.borrow().len() as u32) <= self.fail_first {
                anyhow::bail!("relay busy");
            }
            match self.calls.get(call_id) {
                Some(Some(ports)) => {
                    let addr = self
                        .addresses
                        .get(call_id)
                        .map_or(RELAY_IP, String::as_str)
                        .to_owned();
                    Ok(ControlReply::Call(CallView {
                        call_id: call_id.to_owned(),
                        tags: vec![RelayTag {
                            tag: "from-tag".to_owned(),
                            in_dialogue_with: vec!["to-tag".to_owned()],
                            codec: Some("PCMU".to_owned()),
                            streams: ports
                                .iter()
                                .map(|p| RelayStream {
                                    local_address: addr.clone(),
                                    local_port: *p,
                                    endpoint: None,
                                    advertised_endpoint: None,
                                    is_rtcp: p % 2 == 1,
                                    ssrcs: Vec::new(),
                                })
                                .collect(),
                        }],
                    }))
                }
                _ => anyhow::bail!("no such call"),
            }
        }

        fn describe(&self) -> String {
            "203.0.113.7:22222".to_owned()
        }
    }

    /// A relay that could not be reached never said the stream was not its
    /// media. Collapsing the two is how a run that never reached the relay
    /// comes to read as a run that asked and was told "not mine".
    #[test]
    fn a_relay_that_could_not_be_asked_is_not_a_relay_that_said_no() {
        let mut r = Reconciler::new(ScriptedRelay::new(Answer::Fail));
        let p = permit();
        r.at_startup(&p);

        let why = r
            .on_unexplained_stream(&p, relay_ip(), 30000)
            .expect_err("a relay that is down attributes nothing");

        assert!(
            matches!(why, Unattributed::AskFailed { .. }),
            "a relay that could not be reached must report AskFailed, not \
             {why:?} -- an operator reading `does not hold this port` would \
             conclude the stream is not the relay's media, which nothing here \
             established"
        );
    }

    /// The relay answered `list`, but the `query` for that call failed. Its
    /// ports are UNKNOWN, not absent.
    #[test]
    fn a_call_that_could_not_be_read_leaves_its_ports_unknown() {
        let relay =
            ScriptedRelay::new(Answer::Calls(vec!["call-a"], false)).holding("call-a", None);
        let mut r = Reconciler::new(relay);
        let p = permit();
        r.at_startup(&p);

        let why = r
            .on_unexplained_stream(&p, relay_ip(), 30000)
            .expect_err("an unreadable call attributes nothing");

        assert!(
            !matches!(why, Unattributed::RelayDoesNotHoldIt),
            "a port may belong to the call whose query failed, so the answer \
             must not be `the relay does not hold it` -- got {why:?}"
        );
    }

    /// The honest "no" must remain REACHABLE. Without this, every test above
    /// would still pass if `why_not` simply never returned
    /// [`Unattributed::RelayDoesNotHoldIt`] -- and sipnab would have traded a
    /// false denial for a permanent shrug.
    #[test]
    fn a_complete_answer_can_still_say_the_relay_does_not_hold_it() {
        let relay = ScriptedRelay::new(Answer::Calls(vec!["call-a"], false))
            .holding("call-a", Some(vec![30000, 30001]));
        let mut r = Reconciler::new(relay);
        let p = permit();
        r.at_startup(&p);

        let why = r
            .on_unexplained_stream(&p, relay_ip(), 40000)
            .expect_err("40000 is not a port the relay named");

        assert_eq!(
            why,
            Unattributed::RelayDoesNotHoldIt,
            "the relay was reached, enumerated completely and every call was \
             read -- that is the one case where `not mine` is a fact"
        );
    }

    /// One port number on two interfaces is two sockets. rtpengine allocates
    /// from a single port range across every `--interface`, so this is not a
    /// contrived case -- and keying the index on the port alone attributes one
    /// interface's media to the other interface's call.
    #[test]
    fn the_same_port_on_two_interfaces_is_two_different_calls() {
        let relay = ScriptedRelay::new(Answer::Calls(vec!["call-a", "call-b"], false))
            .holding_on("call-a", "203.0.113.7", vec![30000])
            .holding_on("call-b", "198.51.100.9", vec![30000]);
        let mut r = Reconciler::new(relay);
        let p = permit();
        r.at_startup(&p);

        let first = "203.0.113.7".parse().expect("a literal v4 address parses");
        let second = "198.51.100.9".parse().expect("a literal v4 address parses");

        assert_eq!(
            r.on_unexplained_stream(&p, first, 30000)
                .expect("the relay holds this socket")
                .call_id,
            "call-a"
        );
        assert_eq!(
            r.on_unexplained_stream(&p, second, 30000)
                .expect("the relay holds this socket too")
                .call_id,
            "call-b",
            "port 30000 on the second interface belongs to the other call; \
             keying on the port alone would hand back the first one"
        );
        assert_eq!(
            r.attributed_ports(),
            2,
            "two sockets, not one overwriting the other"
        );
    }

    /// What the relay already said is not said again. Re-handing the startup
    /// snapshot would re-stamp every endpoint with a fresh time, and the
    /// store measures its staleness bound from that stamp -- so a replayed
    /// index would make every endpoint look perpetually current.
    #[test]
    fn a_socket_already_handed_over_is_not_handed_over_twice() {
        let relay = ScriptedRelay::new(Answer::Calls(vec!["call-a"], false))
            .holding("call-a", Some(vec![30000, 30001]));
        let mut r = Reconciler::new(relay);
        let p = permit();
        r.at_startup(&p);

        let t0 = chrono::DateTime::from_timestamp(1_700_000_000, 0).expect("valid");
        let first = r.take_new_links(t0);
        assert_eq!(first.links.len(), 2, "both ports the relay named");
        assert_eq!(first.taken_at, Some(t0));

        let second = r.take_new_links(t0);
        assert!(
            second.links.is_empty(),
            "nothing new was learned between the two calls"
        );
        assert_eq!(
            second.taken_at, None,
            "an empty hand-over must not claim the relay answered at a time"
        );
    }

    /// A refresh hands over only what IT learned, stamped with when the relay
    /// answered rather than when a store happened to be written to.
    #[test]
    fn a_refresh_hands_over_only_what_it_learned() {
        let relay = ScriptedRelay::new(Answer::Calls(vec!["call-a"], false))
            .holding("call-a", Some(vec![30000]))
            .failing_first(1);
        let mut r = Reconciler::new(relay);
        let p = permit();
        r.at_startup(&p);

        let t0 = chrono::DateTime::from_timestamp(1_700_000_000, 0).expect("valid");
        assert!(
            r.take_new_links(t0).links.is_empty(),
            "the startup query failed, so nothing was learned"
        );

        // The refresh retries the call and this time it answers.
        assert!(r.on_unexplained_stream(&p, relay_ip(), 30000).is_ok());

        let t1 = chrono::DateTime::from_timestamp(1_700_000_060, 0).expect("valid");
        let handed = r.take_new_links(t1);
        assert_eq!(handed.links.len(), 1);
        assert_eq!(handed.links[0].port, 30000);
        assert_eq!(
            handed.taken_at,
            Some(t1),
            "stamped with the refresh, not with the startup that learned nothing"
        );
    }

    /// Startup happens once. There is no second startup.
    #[test]
    fn startup_asks_once_and_never_again() {
        let relay = ScriptedRelay::new(Answer::Calls(vec!["call-a"], false))
            .holding("call-a", Some(vec![30000]));
        let mut r = Reconciler::new(relay);
        let p = permit();

        assert!(r.at_startup(&p).is_some(), "the first startup asks");
        let after_first = r.transactions();

        for _ in 0..10 {
            assert!(
                r.at_startup(&p).is_none(),
                "a second startup must ask nothing"
            );
        }
        assert_eq!(
            r.transactions(),
            after_first,
            "repeated startups must not spend transactions"
        );
    }

    /// The not-a-poller proof, stated as a number: a port the snapshot already
    /// explains costs NO control traffic, however often it is seen.
    #[test]
    fn an_explained_port_costs_no_control_traffic() {
        let relay = ScriptedRelay::new(Answer::Calls(vec!["call-a"], false))
            .holding("call-a", Some(vec![30000]));
        let mut r = Reconciler::new(relay);
        let p = permit();
        r.at_startup(&p);
        let after_startup = r.transactions();

        for _ in 0..1000 {
            assert!(
                r.on_unexplained_stream(&p, relay_ip(), 30000).is_ok(),
                "the snapshot explains this port"
            );
        }

        assert_eq!(
            r.transactions(),
            after_startup,
            "1000 sightings of a known port must cost zero further \
             transactions -- any growth here means a poller was built by \
             accident"
        );
    }

    /// An UNEXPLAINED port is asked about once for the run, not once per
    /// packet. This is the arm that would turn a busy capture into a flood.
    #[test]
    fn an_unexplained_port_is_asked_about_once() {
        let relay = ScriptedRelay::new(Answer::Calls(vec!["call-a"], false))
            .holding("call-a", Some(vec![30000]));
        let mut r = Reconciler::new(relay);
        let p = permit();
        r.at_startup(&p);
        let after_startup = r.transactions();

        for _ in 0..500 {
            assert!(r.on_unexplained_stream(&p, relay_ip(), 40000).is_err());
        }

        assert_eq!(
            r.transactions() - after_startup,
            1,
            "500 sightings of one unexplained port must cost a single refresh"
        );
    }

    /// The ceiling does not depend on the traffic. A capture full of distinct
    /// orphan ports cannot buy more control transactions than the run allows.
    #[test]
    fn the_ceiling_bounds_the_run_whatever_the_traffic() {
        let relay = ScriptedRelay::new(Answer::Calls(vec!["call-a"], false))
            .holding("call-a", Some(vec![30000]));
        let mut r = Reconciler::new(relay).with_budget(5);
        let p = permit();
        r.at_startup(&p);

        let mut last = None;
        for port in 40000..40200_u16 {
            last = Some(r.on_unexplained_stream(&p, relay_ip(), port).unwrap_err());
        }

        assert!(
            r.transactions() <= 5,
            "200 distinct orphan ports spent {} transactions against a \
             ceiling of 5",
            r.transactions()
        );
        assert_eq!(
            last,
            Some(Unattributed::BudgetSpent),
            "once the ceiling is reached sipnab must SAY the port was never \
             asked about, not imply the relay disowned it"
        );
    }

    /// A capped list is not a complete one, and a port missing from it proves
    /// nothing.
    #[test]
    fn a_truncated_enumeration_is_not_an_empty_one() {
        let relay = ScriptedRelay::new(Answer::Calls(vec!["call-a"], true))
            .holding("call-a", Some(vec![30000]));
        let mut r = Reconciler::new(relay);
        let p = permit();
        r.at_startup(&p);

        assert!(r.enumeration_was_partial(), "the relay said it had more");
        assert_eq!(
            r.on_unexplained_stream(&p, relay_ip(), 40000).unwrap_err(),
            Unattributed::EnumerationWasPartial,
            "a port absent from a PARTIAL list may belong to a call the list \
             never named"
        );
    }

    /// A call whose query failed is retried on the next refresh. Writing it
    /// off for the run would make a transient relay hiccup permanent, and the
    /// budget -- not a one-shot latch -- is what bounds the retries.
    #[test]
    fn a_call_that_failed_once_is_retried_not_written_off() {
        let relay = ScriptedRelay::new(Answer::Calls(vec!["call-a"], false))
            .holding("call-a", Some(vec![30000]))
            .failing_first(1);
        let mut r = Reconciler::new(relay);
        let p = permit();
        r.at_startup(&p);

        assert_eq!(
            r.attributed_ports(),
            0,
            "the first query failed, so nothing is attributed yet"
        );

        assert!(
            r.on_unexplained_stream(&p, relay_ip(), 30000).is_ok(),
            "the refresh retries the call that failed, and this time it \
             answers -- a port the relay genuinely holds must not stay \
             unattributed because of one transient failure"
        );
    }

    /// A relay that DECLINED the question was reached and understood it, but
    /// it still never said this port is unheld.
    #[test]
    fn a_refusal_is_not_an_empty_relay() {
        let mut r = Reconciler::new(ScriptedRelay::new(Answer::Refuse("not authorized")));
        let p = permit();
        r.at_startup(&p);

        let why = r
            .on_unexplained_stream(&p, relay_ip(), 30000)
            .expect_err("a refusal attributes nothing");

        assert!(
            !matches!(why, Unattributed::RelayDoesNotHoldIt),
            "a refused enumeration establishes nothing about this port -- got {why:?}"
        );
    }

    /// A relay whose enumeration CHANGES between refreshes.
    ///
    /// This is what a port pool does: a call ends, its port is freed, and a
    /// later call is handed the same one. `ScriptedRelay` answers every `list`
    /// identically and so cannot express it.
    struct ReassigningRelay {
        /// One enumeration per `list`; the last entry repeats.
        script: Vec<Vec<&'static str>>,
        /// The relay-side port(s) every call in the script holds.
        ports: Vec<u16>,
        /// When set, each call reports the port TWICE -- once as RTP and once
        /// as RTCP, which is what RFC 5761 multiplexing looks like from a
        /// relay that reports both on one socket.
        muxed: bool,
        lists: RefCell<usize>,
    }

    impl ReassigningRelay {
        fn new(script: Vec<Vec<&'static str>>, ports: Vec<u16>) -> Self {
            Self {
                script,
                ports,
                muxed: false,
                lists: RefCell::new(0),
            }
        }

        fn muxed(mut self) -> Self {
            self.muxed = true;
            self
        }
    }

    impl ReadOnlyRelay for ReassigningRelay {
        fn list(&self, _permit: &TransmitPermit, _limit: u32) -> anyhow::Result<ControlReply> {
            let mut n = self.lists.borrow_mut();
            let ids = &self.script[(*n).min(self.script.len() - 1)];
            *n += 1;
            Ok(ControlReply::Calls(Enumeration {
                call_ids: ids.iter().map(|s| (*s).to_owned()).collect(),
                truncated: false,
            }))
        }

        fn query(&self, _permit: &TransmitPermit, call_id: &str) -> anyhow::Result<ControlReply> {
            let mut streams: Vec<RelayStream> = self
                .ports
                .iter()
                .map(|port| RelayStream {
                    local_address: RELAY_IP.to_owned(),
                    local_port: *port,
                    endpoint: None,
                    advertised_endpoint: None,
                    is_rtcp: false,
                    ssrcs: Vec::new(),
                })
                .collect();
            if self.muxed {
                streams.push(RelayStream {
                    local_address: RELAY_IP.to_owned(),
                    local_port: self.ports[0],
                    endpoint: None,
                    advertised_endpoint: None,
                    is_rtcp: true,
                    ssrcs: Vec::new(),
                });
            }
            Ok(ControlReply::Call(CallView {
                call_id: call_id.to_owned(),
                tags: vec![RelayTag {
                    tag: format!("tag-of-{call_id}"),
                    in_dialogue_with: Vec::new(),
                    codec: Some("PCMU".to_owned()),
                    streams,
                }],
            }))
        }

        fn describe(&self) -> String {
            format!("{RELAY_IP}:2223")
        }
    }

    /// A relay port handed to a NEW call is handed on to the store again.
    ///
    /// [`Reconciler::absorb`] used to record a socket as new only when the
    /// index insert was the FIRST for that socket, so a reassignment updated
    /// the index and was never reported. The store kept the previous call's
    /// endpoint, and media on that port was credited to a call that had ended
    /// -- not left unattributed, but attributed to the WRONG call, for the
    /// 300 s the endpoint stays live.
    #[test]
    fn a_reused_relay_port_is_reported_again_with_its_new_call() {
        let p = permit();
        let mut r = Reconciler::new(ReassigningRelay::new(
            vec![vec!["call-A"], vec!["call-B"]],
            vec![30000],
        ));

        r.at_startup(&p);
        let first = r.take_new_links(chrono::Utc::now());
        assert_eq!(
            first
                .links
                .iter()
                .map(|l| l.call_id.as_str())
                .collect::<Vec<_>>(),
            vec!["call-A"],
            "startup registers the port against the call that held it"
        );

        // Any unexplained socket refreshes the snapshot, and the relay now
        // reports call-B holding the port call-A had.
        let _ = r.on_unexplained_stream(&p, "198.51.100.9".parse().expect("valid"), 41234);

        let reported: Vec<String> = r
            .take_new_links(chrono::Utc::now())
            .links
            .iter()
            .filter(|l| l.port == 30000)
            .map(|l| l.call_id.clone())
            .collect();
        assert_eq!(
            reported,
            vec!["call-B".to_owned()],
            "the index learned the reassignment; the store has to learn it too, \
             or media on this port stays credited to call-A"
        );
    }

    /// ...and a socket the relay reports twice for ONE call is reported once.
    ///
    /// The bound on the fix above. Re-reporting a socket whose call has not
    /// changed would re-date the endpoint every time the relay repeats itself,
    /// and the store's 300 s staleness clock measures from when the relay SAID
    /// it -- so a socket that keeps being re-stamped never goes stale and the
    /// bound quietly stops existing. A relay multiplexing RTP and RTCP on one
    /// port (RFC 5761) reports exactly this shape.
    #[test]
    fn a_socket_repeated_within_one_call_is_reported_only_once() {
        let p = permit();
        let mut r =
            Reconciler::new(ReassigningRelay::new(vec![vec!["call-A"]], vec![30000]).muxed());

        r.at_startup(&p);
        let links = r.take_new_links(chrono::Utc::now());
        let for_port: Vec<&RelayLink> = links.links.iter().filter(|l| l.port == 30000).collect();
        assert_eq!(
            for_port.len(),
            1,
            "one socket, one call, one link -- got {for_port:?}"
        );
    }

    /// Drain the hand-over and name the call(s) reported for one port.
    fn named<R: ReadOnlyRelay>(r: &mut Reconciler<R>, port: u16) -> Vec<String> {
        r.take_new_links(chrono::Utc::now())
            .links
            .iter()
            .filter(|l| l.port == port)
            .map(|l| l.call_id.clone())
            .collect()
    }

    /// A port reassigned TWICE is handed over both times.
    ///
    /// One reassignment is the case above. This is the one that fails on a
    /// plausible half-fix -- firing the hand-over only on the FIRST change
    /// repairs the reported symptom and leaves every later recycle silent.
    #[test]
    fn a_port_reassigned_twice_is_handed_over_each_time() {
        let p = permit();
        let mut r = Reconciler::new(ReassigningRelay::new(
            vec![vec!["call-A"], vec!["call-B"], vec!["call-C"]],
            vec![30000],
        ));
        let other: IpAddr = "198.51.100.9".parse().expect("valid");

        r.at_startup(&p);
        assert_eq!(named(&mut r, 30000), vec!["call-A".to_owned()], "startup");

        let _ = r.on_unexplained_stream(&p, other, 41234);
        assert_eq!(
            named(&mut r, 30000),
            vec!["call-B".to_owned()],
            "first reassignment"
        );

        let _ = r.on_unexplained_stream(&p, other, 41235);
        assert_eq!(
            named(&mut r, 30000),
            vec!["call-C".to_owned()],
            "second reassignment -- a port recycled again is news again"
        );
    }

    /// Two ports reassigned in ONE refresh are both handed over.
    ///
    /// The hand-over skips a socket already queued, and this proves the skip
    /// is per-socket rather than per-refresh: a guard written as "something
    /// changed, so push once" reports one of these and drops the other,
    /// leaving half the call's media on the ended call.
    #[test]
    fn two_ports_reassigned_in_one_refresh_are_both_handed_over() {
        let p = permit();
        let mut r = Reconciler::new(ReassigningRelay::new(
            vec![vec!["call-A"], vec!["call-B"]],
            vec![30000, 30002],
        ));

        r.at_startup(&p);
        let _ = r.take_new_links(chrono::Utc::now());

        let _ = r.on_unexplained_stream(&p, "198.51.100.9".parse().expect("valid"), 41234);

        let mut got: Vec<(u16, String)> = r
            .take_new_links(chrono::Utc::now())
            .links
            .iter()
            .map(|l| (l.port, l.call_id.clone()))
            .collect();
        got.sort_unstable();
        assert_eq!(
            got,
            vec![(30000, "call-B".to_owned()), (30002, "call-B".to_owned())],
            "both recycled ports have to reach the store"
        );
    }
}
