// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

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
//! - **Never periodic.** There is no timer and no interval in this module.
//!   It acts when it is called, and it is called from exactly two places:
//!   once at startup, and when a stream turns up that no signaling explains.
//!   A poller cannot be built out of these pieces by accident -- it would have
//!   to be written on purpose, somewhere else. The only threads are the ones
//!   [`Reconcilers::at_startup`] asks every engine on at once, one per engine,
//!   and each is joined before it returns.
//! - **Once per question.** Startup latches. Each relay-side port is asked
//!   about once, so a stream that stays unexplained -- which is the normal
//!   case for traffic the relay is not handling at all -- does not re-ask on
//!   every packet. A port is REMEMBERED as asked about only while the budget
//!   below has room: past that nothing is remembered, because nothing will be
//!   asked. The memory holds at most [`SOCKET_MEMORY`] sockets, oldest
//!   forgotten first, so the set does not grow with the length of the run
//!   either; a forgotten socket asked about again spends a transaction like
//!   any other ask.
//! - **A budget that does not depend on the traffic.** Each engine spends
//!   from a [`super::budget::TransactionBudget`]: a burst of
//!   [`DEFAULT_BUDGET`] (or whatever [`Reconciler::with_budget`] was given)
//!   that refills at [`super::budget::DEFAULT_REFILL`], 33 transactions an
//!   hour. A capture full of orphans cannot turn into a flood of control
//!   traffic, a run of days still names a call set up late, and when the
//!   budget is empty sipnab SAYS so rather than quietly attributing nothing.
//!   A complete enumeration forgets the calls it no longer names, so the
//!   index holds what the engine holds rather than every call the run saw.
//! - **One reach past a capped answer, per run.** A relay that returns a
//!   capped enumeration is asked ONCE more, for [`WIDE_LIST_LIMIT`], because
//!   covering 32 of 400 calls reports the other 368 as orphans and looks like
//!   it worked. The size of that second ask is deliberately past what a
//!   datagram can carry, so an implementation with no stream transport fails
//!   it -- which is how "where available" is discovered rather than declared.
//!   It is attempted once whether it succeeds or fails, and either way the
//!   summary SAYS which happened: "we never tried" and "we tried and could
//!   not" send an operator to different places.
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
use super::types::{CallView, ControlReply};
#[cfg(all(not(target_arch = "wasm32"), feature = "native"))]
use crate::security::transmit_guard::TransmitPermit;
#[cfg(all(not(target_arch = "wasm32"), feature = "native"))]
use std::sync::Arc;

/// Where a reconciler reads the time: the system's monotonic clock, or a
/// test's.
#[cfg(all(not(target_arch = "wasm32"), feature = "native"))]
pub type Clock = Arc<dyn Fn() -> std::time::Instant + Send + Sync>;

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

    /// Ask the relay for its own counters.
    ///
    /// Behind the same [`TransmitPermit`] as the other two, for the same
    /// reason: this puts a packet on the network, and every other thing sipnab
    /// reports comes from bytes it already holds. An API caller or an agent
    /// asking a question that needs counters can have them; a run nobody asked
    /// anything of sends nothing.
    ///
    /// # Errors
    ///
    /// When the relay cannot be reached, or answers something this cannot read.
    fn statistics(&self, permit: &TransmitPermit) -> anyhow::Result<ControlReply>;

    /// Ask the relay for its counters about ONE call, by Call-ID.
    ///
    /// The per-call companion of [`statistics`](Self::statistics): the relay's
    /// own numbers for a single call, flattened to name/value pairs the same
    /// way. Behind the same permit and for the same reason. The default refuses,
    /// so a relay that has no per-call form (or a test double) is not forced to
    /// invent one; the implementations that can answer override it.
    ///
    /// # Errors
    ///
    /// When the relay cannot be reached, answers something this cannot read, or
    /// does not support a per-call query.
    fn call_statistics(
        &self,
        _permit: &TransmitPermit,
        _call_id: &str,
    ) -> anyhow::Result<ControlReply> {
        anyhow::bail!("this relay has no per-call statistics form")
    }

    /// The relay as the subject of a sentence an operator reads, kind and
    /// address together: `rtpengine at 192.0.2.1:2223`. Callers write
    /// `"{describe}: ..."` and never add the kind again.
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
    /// Whether the relay holds this port for a side that CONSUMES the call's
    /// media rather than for a leg of it.
    ///
    /// A recording or forwarding fork is a side of the call in its own right,
    /// with its own relay ports, so its media is genuinely this call's and is
    /// attributed to it. It is still not a party to the call, and a consumer
    /// that cannot tell the difference reports a two-party call as having
    /// three parties.
    pub is_media_subscriber: bool,
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
    /// The transaction budget was empty, so this port was not asked about.
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
            Self::BudgetSpent => "the control-transaction budget was empty, so this port was \
                 not asked about"
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
/// datagram. [`crate::relay::types::Enumeration::truncated`] is what keeps a capped answer from
/// reading as a complete one.
pub const DEFAULT_LIST_LIMIT: u32 = 32;

/// How many Call-IDs to ask for when a capped answer has to be reached past.
///
/// A CHOICE, and one bounded at the far end by measurement rather than by
/// taste. [`DEFAULT_LIST_LIMIT`] exists because a relay's own documentation
/// warns that a bigger answer may not fit in a datagram; a transport that
/// streams has no datagram to overflow, so the cap becomes what sipnab is
/// willing to read back.
///
/// Measured against a relay holding 1200 calls with 55-character Call-IDs: an
/// answer of 1000 of them is 61034 bytes and one of 1200 is 73234, and the
/// second is past what any UDP datagram can carry -- the request draws no
/// reply at all rather than a short one. 1024 sits between those two, which
/// is the point: it is a number a datagram cannot be relied on to return and
/// a stream returns without difficulty.
pub const WIDE_LIST_LIMIT: u32 = 1024;

/// The most control transactions one engine's budget holds: its burst.
///
/// Enough for a full startup snapshot (one `list` plus a `query` per call at
/// the default limit) and a comparable refresh afterwards. The point is that
/// the burst does not depend on how much traffic the capture carries: a
/// capture full of orphans cannot turn into a flood of control traffic. The
/// budget refills at [`super::budget::DEFAULT_REFILL`] and never holds more
/// than this.
pub const DEFAULT_BUDGET: u32 = 2 * (DEFAULT_LIST_LIMIT + 1);

/// How many asked-about sockets one engine's reconciler remembers.
///
/// Each socket in the set cost a transaction, and the budget refills, so over
/// a long run the set would grow with the run's length. Past this many the
/// oldest is forgotten. A forgotten socket that turns up again is asked about
/// again, which spends a transaction like any other ask, so the budget still
/// bounds the traffic. At the default refill of 33 an hour, filling it takes
/// more than five days of transactions spent on nothing else.
pub const SOCKET_MEMORY: usize = 4096;

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
    /// Whether this run has already reached past a capped enumeration.
    ///
    /// Once for the run, not once per refresh: a relay with no transport that
    /// can carry a wider answer refuses the same way every time, and asking it
    /// again on every refresh is a packet spent on a question already answered.
    wide_enumeration_attempted: bool,
    /// Why the wider enumeration could not be read, when one was tried and
    /// failed.
    ///
    /// Held apart from [`Self::last_ask_failure`] because the relay was
    /// reached: the capped answer is real and is still used. Only the reach
    /// past it failed, and "we never tried" and "we tried and could not" send
    /// an operator to different places.
    wide_enumeration_failure: Option<String>,
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
    /// Calls the last enumeration named that the ceiling left unread --
    /// neither read nor failed, because their turn never came.
    ///
    /// While any remain, a port missing from the index may be one of theirs,
    /// so the ceiling rather than the relay is why it is unattributed, even
    /// for a port that was asked about.
    calls_never_read: usize,
    /// Transactions spent so far this run.
    spent: u32,
    /// What this engine may still spend: a burst that does not depend on how
    /// much traffic the capture carries, refilled over time.
    budget: super::budget::TransactionBudget,
    /// Where the budget reads the time.
    clock: Clock,
    /// The most sockets [`Self::asked_ports`] remembers.
    socket_memory: usize,
    /// [`Self::asked_ports`] in the order they were asked about, oldest
    /// first, so the oldest is the one forgotten.
    asked_order: std::collections::VecDeque<(IpAddr, u16)>,
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
            wide_enumeration_attempted: false,
            wide_enumeration_failure: None,
            last_ask_failure: None,
            new_since_take: Vec::new(),
            unread_calls: HashSet::new(),
            calls_never_read: 0,
            spent: 0,
            budget: super::budget::TransactionBudget::new(
                DEFAULT_BUDGET,
                Some(super::budget::DEFAULT_REFILL),
                std::time::Instant::now(),
            ),
            clock: Arc::new(std::time::Instant::now),
            socket_memory: SOCKET_MEMORY,
            asked_order: std::collections::VecDeque::new(),
            list_limit: DEFAULT_LIST_LIMIT,
        }
    }

    /// Override the burst: the most transactions a full budget holds. The
    /// budget starts full.
    #[must_use]
    pub fn with_budget(mut self, budget: u32) -> Self {
        self.budget =
            super::budget::TransactionBudget::new(budget, self.budget.refill(), (self.clock)());
        self
    }

    /// Override how fast the budget refills; `None` never refills, a ceiling
    /// for the run. The budget starts full.
    #[must_use]
    pub fn with_refill(mut self, refill: Option<super::budget::Refill>) -> Self {
        self.budget =
            super::budget::TransactionBudget::new(self.budget.burst(), refill, (self.clock)());
        self
    }

    /// Read the time from `clock` rather than the system's monotonic clock.
    /// The budget starts full at the clock's first reading.
    #[must_use]
    pub fn with_clock(mut self, clock: Clock) -> Self {
        self.clock = clock;
        self.budget = super::budget::TransactionBudget::new(
            self.budget.burst(),
            self.budget.refill(),
            (self.clock)(),
        );
        self
    }

    /// Override how many asked-about sockets are remembered.
    #[must_use]
    pub fn with_socket_memory(mut self, sockets: usize) -> Self {
        self.socket_memory = sockets;
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

    /// The burst: the most transactions a full budget holds.
    ///
    /// Exposed beside [`Self::transactions`] and [`Self::available`] so a
    /// report can state all three -- "8 spent, 58 of 66 left" says whether the
    /// run was bounded by the relay or by sipnab.
    #[must_use]
    pub fn budget(&self) -> u32 {
        self.budget.burst()
    }

    /// Transactions the budget holds now.
    #[must_use]
    pub fn available(&self) -> u32 {
        self.budget.available((self.clock)())
    }

    /// How fast the budget refills, `None` when it does not.
    #[must_use]
    pub fn refill(&self) -> Option<super::budget::Refill> {
        self.budget.refill()
    }

    /// How long until the budget holds one more transaction, `None` when it
    /// is full or does not refill.
    #[must_use]
    pub fn next_refill_in(&self) -> Option<std::time::Duration> {
        self.budget.next_in((self.clock)())
    }

    /// Whether the budget has a transaction to spend now.
    fn has_room(&self) -> bool {
        self.available() > 0
    }

    /// Ports the relay accounted for.
    #[must_use]
    pub fn attributed_ports(&self) -> usize {
        self.index.len()
    }

    /// Sockets this run is remembering it has already asked about.
    ///
    /// Exposed for the reason [`Self::transactions`] is: "does this grow with
    /// the traffic?" is a question about a NUMBER, and a test that cannot read
    /// the number cannot answer it. Bounded by [`Self::budget`], since a
    /// socket is recorded only when there is still a transaction to spend on
    /// asking about it.
    #[must_use]
    pub fn tracked_sockets(&self) -> usize {
        self.asked_ports.len()
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
            // The query path speaks only to rtpengine; a second relay with a
            // read-only control surface would set this itself.
            implementation: crate::relay::RelayImplementation::Rtpengine,
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
            // The query path speaks only to rtpengine; a second relay with a
            // read-only control surface would set this itself.
            implementation: crate::relay::RelayImplementation::Rtpengine,
            taken_at: (!links.is_empty()).then_some(taken_at),
            links,
        }
    }

    /// Spend one transaction, or refuse.
    fn spend(&mut self) -> bool {
        if !self.budget.try_spend((self.clock)()) {
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
        // The ceiling is consulted BEFORE the socket is recorded. `asked_ports`
        // exists to stop a SECOND ask, and once the ceiling is spent there is
        // no second ask to stop -- so recording one costs an entry that buys
        // nothing and is never released. Recorded after the check, the set grew
        // by one per distinct socket for the life of the run, which is a bound
        // that depends on how much traffic the capture carries: the one thing
        // the bounds at the top of this module say they do not do. Checked
        // first, the set cannot outgrow the ceiling, because every entry in it
        // cost a transaction.
        if !self.has_room() {
            return Err(self.why_not(socket));
        }
        if !self.remember_asked(socket) {
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
    ///
    /// A spent ceiling explains THIS socket only when the socket was never
    /// asked about, or when the ceiling left enumerated calls unread. The
    /// socket whose own refresh spent the last transaction was asked, and if
    /// that refresh read every call the relay named, its answer stands.
    fn why_not(&self, socket: (IpAddr, u16)) -> Unattributed {
        if let Some(reason) = &self.last_ask_failure {
            Unattributed::AskFailed {
                reason: reason.clone(),
            }
        } else if !self.has_room()
            && (!self.asked_ports.contains(&socket) || self.calls_never_read > 0)
        {
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
                "{}: not asked -- {}",
                self.relay.describe(),
                Unattributed::BudgetSpent.describe()
            );
        }
        let narrow_limit = self.list_limit;
        let mut enumeration = match self.relay.list(permit, self.list_limit) {
            Ok(ControlReply::Calls(e)) => e,
            Ok(ControlReply::Refused { reason }) => {
                self.last_ask_failure = Some(format!("the relay refused: {reason}"));
                return format!(
                    "{} refused to enumerate its calls: {reason}",
                    self.relay.describe()
                );
            }
            Ok(other) => {
                self.last_ask_failure =
                    Some("the relay answered a `list` with something else".to_owned());
                return format!(
                    "{} answered a `list` with something else ({other:?})",
                    self.relay.describe()
                );
            }
            Err(e) => {
                self.last_ask_failure = Some(format!("{e:#}"));
                return format!(
                    "{} could not be asked which calls are up: {e:#}",
                    self.relay.describe()
                );
            }
        };
        // The relay answered. Whatever went wrong last time no longer governs.
        self.last_ask_failure = None;

        // THE REACH HALF. A capped answer is not an answer about the relay, it
        // is an answer about the transport that carried it: the calls past the
        // cap were never named, and their streams arrive looking like orphans.
        // So a capped answer is followed by ONE wider ask, whose size is
        // deliberately past what a datagram can return -- an implementation
        // that can only answer over a datagram fails it, which is exactly the
        // "where available" test, discovered rather than declared.
        let mut reached_wider = false;
        if enumeration.truncated
            && !self.wide_enumeration_attempted
            && narrow_limit < WIDE_LIST_LIMIT
        {
            self.wide_enumeration_attempted = true;
            if self.spend() {
                match self.relay.list(permit, WIDE_LIST_LIMIT) {
                    Ok(ControlReply::Calls(wider)) => {
                        // Adopted for the rest of the run: a relay that
                        // answered a wider question once will answer it again,
                        // and starting every later refresh from the capped
                        // limit would spend a transaction rediscovering that.
                        self.list_limit = WIDE_LIST_LIMIT;
                        enumeration = wider;
                        reached_wider = true;
                    }
                    Ok(ControlReply::Refused { reason }) => {
                        self.wide_enumeration_failure =
                            Some(format!("the relay refused: {reason}"));
                    }
                    Ok(_) => {
                        self.wide_enumeration_failure =
                            Some("the relay answered it with something else".to_owned());
                    }
                    Err(e) => self.wide_enumeration_failure = Some(format!("{e:#}")),
                }
            } else {
                self.wide_enumeration_failure =
                    Some("the control-transaction budget was already empty".to_owned());
            }
        }
        self.enumeration_partial = enumeration.truncated;
        if !enumeration.truncated {
            self.forget_ended(&enumeration.call_ids);
        }

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
        // Calls the enumeration named that this run never even asked about.
        // Neither read nor failed: the ceiling ran out before their turn. The
        // reach half moves the binding constraint here, and "40 enumerated, 10
        // queried" is arithmetic an operator should not have to do to learn
        // that thirty calls' streams will read as orphans.
        let never_read = enumeration
            .call_ids
            .iter()
            .filter(|c| !self.known_calls.contains(*c) && !self.unread_calls.contains(*c))
            .count();
        self.calls_never_read = never_read;

        let mut line = format!(
            "{}: {}; queried {queried} of them, {} relay port(s) \
             now attributable",
            self.relay.describe(),
            enumeration.describe(),
            self.index.len()
        );
        if reached_wider {
            line.push_str(&format!(
                ". The first answer was capped at {narrow_limit}, so the relay \
                 was asked once more for up to {WIDE_LIST_LIMIT} and this is \
                 that wider answer"
            ));
        } else if let Some(why) = &self.wide_enumeration_failure
            && self.enumeration_partial
        {
            line.push_str(&format!(
                ". A wider ask for up to {WIDE_LIST_LIMIT} was attempted and \
                 failed ({why}), so this list stays capped at {narrow_limit} -- \
                 the calls past that were never named, and their streams will \
                 arrive looking like orphans"
            ));
        }
        if never_read > 0 {
            line.push_str(&format!(
                ". {never_read} call(s) were never read because the \
                 control-transaction budget ran out, so their ports stay \
                 unattributed"
            ));
        }
        if failed > 0 {
            line.push_str(&format!(
                ". {failed} call(s) could not be read, so their ports stay \
                 unattributed -- that is a gap in this snapshot, not evidence \
                 those streams are unattached"
            ));
        }
        // Counted over the INDEX rather than over this refresh's tags: the
        // question an operator is asking is about the ports now attributable,
        // which is what the number beside it counts.
        let subscriber_ports = self
            .index
            .values()
            .filter(|a| a.is_media_subscriber)
            .count();
        if subscriber_ports > 0 {
            line.push_str(&format!(
                ". {subscriber_ports} of those port(s) are held by a media \
                 subscriber -- a recording or forwarding consumer of the call \
                 rather than a leg of it -- so a two-party call legitimately \
                 shows more relay-side streams than it has parties"
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
        if !self.has_room() {
            line.push_str(&match self.refill() {
                Some(refill) => format!(
                    ". The control-transaction budget is now empty; it refills \
                     at {refill}, up to {}, so a stream that turns up later is \
                     asked about once it has",
                    self.budget()
                ),
                None => ". The control-transaction ceiling for this run is now \
                         spent, so no further questions will be asked"
                    .to_owned(),
            });
        }
        line
    }

    /// Forget every call a complete enumeration no longer names, and its
    /// sockets.
    ///
    /// The budget refills, so over a run of days the reconciler reads far
    /// more calls than one snapshot holds. A call the engine no longer holds
    /// has ended, and keeping it would grow the index with the run's length.
    /// Only a COMPLETE enumeration says a call ended: a capped one says
    /// nothing about the calls past the cap.
    fn forget_ended(&mut self, listed: &[String]) {
        let listed: HashSet<&str> = listed.iter().map(String::as_str).collect();
        self.known_calls.retain(|c| listed.contains(c.as_str()));
        self.unread_calls.retain(|c| listed.contains(c.as_str()));
        self.index
            .retain(|_, a| listed.contains(a.call_id.as_str()));
    }

    /// Record that `socket` was asked about. False when it already was.
    fn remember_asked(&mut self, socket: (IpAddr, u16)) -> bool {
        if !self.asked_ports.insert(socket) {
            return false;
        }
        self.asked_order.push_back(socket);
        while self.asked_order.len() > self.socket_memory {
            if let Some(oldest) = self.asked_order.pop_front() {
                self.asked_ports.remove(&oldest);
            }
        }
        true
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
                        is_media_subscriber: tag.is_media_subscriber(),
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
/// three unlabeled fields whose order is a guess.
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
    /// Which relay answered.
    ///
    /// sipnab opened this connection itself, so it knows -- and a consumer
    /// reading a media anchor needs it, because the two relays have different
    /// trust properties (RP3).
    pub implementation: crate::relay::RelayImplementation,
}

#[cfg(all(not(target_arch = "wasm32"), feature = "native"))]
impl<R: ReadOnlyRelay> From<Reconciler<R>> for Reconcilers<R> {
    /// The one engine a run without engine rules asks.
    fn from(one: Reconciler<R>) -> Self {
        Self::new(vec![one])
    }
}

/// What [`Reconcilers::on_unexplained_stream`] learned about one socket.
#[derive(Debug, Clone)]
pub struct EnginesAnswer {
    /// The engine that attributed it, by index, and what it said.
    pub found: Option<(usize, Attribution)>,
    /// Each engine asked that could not attribute it, by index, and why.
    pub why_not: Vec<(usize, Unattributed)>,
}

/// One [`Reconciler`] per listed engine, asked together.
///
/// Startup asks every engine the run lists at once: `--rtpengine-control`,
/// then each other engine an engine map row or an ng engine row names. Each
/// engine keeps its own index, its own record of what was asked, and its own
/// transaction budget, so one busy engine cannot spend another's.
///
/// A stream nothing explains is still asked of each engine in turn, stopping
/// at the first that holds it. Asking every engine at once would spend a
/// transaction of every engine's budget on a socket only one engine holds,
/// and this ask runs on the reconciler's own thread, never on the packet
/// path or a caller's question.
#[cfg(all(not(target_arch = "wasm32"), feature = "native"))]
pub struct Reconcilers<R: ReadOnlyRelay> {
    /// The engines, `--rtpengine-control` first.
    engines: Vec<Reconciler<R>>,
}

#[cfg(all(not(target_arch = "wasm32"), feature = "native"))]
impl<R: ReadOnlyRelay> Reconcilers<R> {
    /// The engines to ask, `--rtpengine-control` first.
    #[must_use]
    pub fn new(engines: Vec<Reconciler<R>>) -> Self {
        Self { engines }
    }

    /// The engines' reconcilers, in the order given.
    #[must_use]
    pub fn into_engines(self) -> Vec<Reconciler<R>> {
        self.engines
    }

    /// Each engine's reconciler, in the order given.
    #[must_use]
    pub fn engines(&self) -> &[Reconciler<R>] {
        &self.engines
    }

    /// FIRST TRIGGER, on every engine.
    ///
    /// Returns each engine's line, in order, then `Held by several engines:`
    /// naming each call two or more engines read at startup. Empty when
    /// startup has already run.
    pub fn at_startup(&mut self, permit: &TransmitPermit) -> Vec<String>
    where
        R: Send,
    {
        // Every engine at once, each on its own reconciler, so a dead engine
        // costs one control timeout rather than one per engine, and the lines
        // stay in the engines' order.
        let mut lines: Vec<String> = crate::relay::fan_out::ask_each(
            self.engines.iter_mut().collect(),
            |e: &mut Reconciler<R>| e.at_startup(permit),
        )
        .into_iter()
        .flatten()
        .collect();
        if lines.is_empty() {
            return lines;
        }
        let mut held: std::collections::BTreeMap<&str, usize> = std::collections::BTreeMap::new();
        for e in &self.engines {
            for call in &e.known_calls {
                *held.entry(call.as_str()).or_default() += 1;
            }
        }
        let several: Vec<&str> = held
            .into_iter()
            .filter(|(_, n)| *n > 1)
            .map(|(c, _)| c)
            .collect();
        if !several.is_empty() {
            lines.push(format!("Held by several engines: {}", several.join(", ")));
        }
        lines
    }

    /// SECOND TRIGGER, on every engine.
    ///
    /// A socket an engine already accounted for is answered from memory,
    /// asking nothing. Otherwise each engine is asked in turn until one
    /// attributes it. The answer carries the attributing engine's index and
    /// what it said, beside each engine asked before it and why that engine
    /// could not, so an engine that is down is still reported.
    pub fn on_unexplained_stream(
        &mut self,
        permit: &TransmitPermit,
        local_address: IpAddr,
        local_port: u16,
    ) -> EnginesAnswer {
        // What an engine already accounted for costs nothing to answer, so
        // every index is read before any engine is asked.
        if let Some((i, found)) = self
            .engines
            .iter()
            .enumerate()
            .find_map(|(i, e)| e.index.get(&(local_address, local_port)).map(|a| (i, a)))
        {
            return EnginesAnswer {
                found: Some((i, found.clone())),
                why_not: Vec::new(),
            };
        }
        let mut why_not: Vec<(usize, Unattributed)> = Vec::new();
        for (i, engine) in self.engines.iter_mut().enumerate() {
            match engine.on_unexplained_stream(permit, local_address, local_port) {
                Ok(found) => {
                    return EnginesAnswer {
                        found: Some((i, found)),
                        why_not,
                    };
                }
                Err(reason) => why_not.push((i, reason)),
            }
        }
        EnginesAnswer {
            found: None,
            why_not,
        }
    }

    /// What every engine has said since the last call.
    #[must_use]
    pub fn take_new_links(&mut self, taken_at: chrono::DateTime<chrono::Utc>) -> RelaySnapshot {
        let links: Vec<RelayLink> = self
            .engines
            .iter_mut()
            .flat_map(|e| e.take_new_links(taken_at).links)
            .collect();
        RelaySnapshot {
            implementation: crate::relay::RelayImplementation::Rtpengine,
            taken_at: (!links.is_empty()).then_some(taken_at),
            links,
        }
    }
}

#[cfg(test)]
#[cfg(all(not(target_arch = "wasm32"), feature = "native"))]
mod tests {
    use super::*;
    use crate::capture::CaptureSource;
    use crate::relay::types::{Enumeration, RelayStream, RelayTag};
    use std::cell::RefCell;
    type TestError = Box<dyn std::error::Error>;

    /// The address the scripted relay reports for every stream.
    const RELAY_IP: &str = "203.0.113.7";

    /// That same address, parsed, for building lookup keys.
    fn relay_ip() -> Result<std::net::IpAddr, TestError> {
        Ok(RELAY_IP
            .parse()
            .map_err(|e| format!("a literal v4 address parses: {e:?}"))?)
    }

    /// A permit, which only a live source can grant.
    fn permit() -> Result<TransmitPermit, TestError> {
        let live = CaptureSource::Live {
            device: "eth0".to_owned(),
        };
        Ok(TransmitPermit::for_source(&live).ok_or("a live source grants a permit")?)
    }

    /// What a scripted relay should answer with.
    enum Answer {
        Calls(Vec<&'static str>, bool),
        Refuse(&'static str),
        Fail,
        /// A well-formed reply that is not an enumeration at all.
        NotAList,
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
        /// How it describes itself, when not the default.
        name: Option<&'static str>,
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
                name: None,
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

        fn named(mut self, name: &'static str) -> Self {
            self.name = Some(name);
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
                Answer::NotAList => Ok(ControlReply::Statistics(Vec::new())),
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
                            media_subscriptions: Vec::new(),
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
                                    facts: Default::default(),
                                })
                                .collect(),
                        }],
                    }))
                }
                _ => anyhow::bail!("no such call"),
            }
        }

        fn describe(&self) -> String {
            self.name.unwrap_or("203.0.113.7:22222").to_owned()
        }
        fn statistics(
            &self,
            _permit: &crate::security::transmit_guard::TransmitPermit,
        ) -> anyhow::Result<crate::relay::types::ControlReply> {
            // A double, and no test asks it for counters. Refusing is what a
            // relay without statistics support would do, so this is the honest
            // stand-in rather than a fabricated answer.
            anyhow::bail!("this double answers no statistics")
        }
    }

    /// A relay holding one call: two legs, and one side that only subscribes.
    ///
    /// This is what relay-side recording and forking look like from a query:
    /// the subscriber is a side of the call in its own right, with its own
    /// relay ports, because the relay answers about every side it holds and
    /// not only the two that signed the call.
    struct ForkedRelay;

    impl ReadOnlyRelay for ForkedRelay {
        fn list(&self, _permit: &TransmitPermit, _limit: u32) -> anyhow::Result<ControlReply> {
            Ok(ControlReply::Calls(Enumeration {
                call_ids: vec!["call-a".to_owned()],
                truncated: false,
            }))
        }

        fn query(&self, _permit: &TransmitPermit, call_id: &str) -> anyhow::Result<ControlReply> {
            let stream = |port: u16| RelayStream {
                local_address: RELAY_IP.to_owned(),
                local_port: port,
                endpoint: None,
                advertised_endpoint: None,
                is_rtcp: false,
                ssrcs: Vec::new(),
                facts: Default::default(),
            };
            Ok(ControlReply::Call(CallView {
                call_id: call_id.to_owned(),
                tags: vec![
                    RelayTag {
                        tag: "from-tag".to_owned(),
                        in_dialogue_with: vec!["to-tag".to_owned()],
                        media_subscriptions: Vec::new(),
                        codec: Some("PCMU".to_owned()),
                        streams: vec![stream(30000)],
                    },
                    RelayTag {
                        tag: "recorder-1".to_owned(),
                        in_dialogue_with: Vec::new(),
                        media_subscriptions: vec!["from-tag".to_owned()],
                        codec: Some("PCMU".to_owned()),
                        streams: vec![stream(30010)],
                    },
                ],
            }))
        }

        fn describe(&self) -> String {
            "203.0.113.7:22222".to_owned()
        }
        fn statistics(
            &self,
            _permit: &crate::security::transmit_guard::TransmitPermit,
        ) -> anyhow::Result<crate::relay::types::ControlReply> {
            // A double, and no test asks it for counters. Refusing is what a
            // relay without statistics support would do, so this is the honest
            // stand-in rather than a fabricated answer.
            anyhow::bail!("this double answers no statistics")
        }
    }

    /// A recording fork's port belongs to the call. It is not a leg of it.
    ///
    /// Both halves matter and they pull apart. Refusing the port would leave
    /// real media on the relay unexplained; calling it a leg gives a
    /// two-party call three parties, after which the analysis that judges
    /// one-way audio and asymmetry answers a question nobody asked.
    #[test]
    fn a_port_held_by_a_media_subscriber_is_attributed_but_not_called_a_leg()
    -> Result<(), TestError> {
        let mut r = Reconciler::new(ForkedRelay);
        let p = permit()?;
        let summary = r.at_startup(&p).ok_or("startup asks once")?;

        let leg = r
            .on_unexplained_stream(&p, relay_ip()?, 30000)
            .map_err(|e| format!("the leg's port is in the snapshot: {e:?}"))?;
        assert!(
            !leg.is_media_subscriber,
            "a side with an offer/answer peer is a leg of the call"
        );

        let fork = r
            .on_unexplained_stream(&p, relay_ip()?, 30010)
            .map_err(|e| {
                format!(
                    "the fork's port is the relay's media for this call, so \
                     it must still be attributed: {e:?}"
                )
            })?;
        assert_eq!(
            fork.call_id, "call-a",
            "the subscriber's port belongs to the call it forks"
        );
        assert!(
            fork.is_media_subscriber,
            "and it must be marked as a consumer of the call rather than a \
             party to it"
        );

        assert!(
            summary.contains("media subscriber"),
            "the summary an operator reads must SAY that some of the ports it \
             counted are a recording or forwarding fork, or three streams on \
             a two-party call look like a bug in sipnab: {summary}"
        );
        Ok(())
    }

    /// A relay that could not be reached never said the stream was not its
    /// media. Collapsing the two is how a run that never reached the relay
    /// comes to read as a run that asked and was told "not mine".
    #[test]
    fn a_relay_that_could_not_be_asked_is_not_a_relay_that_said_no() -> Result<(), TestError> {
        let mut r = Reconciler::new(ScriptedRelay::new(Answer::Fail));
        let p = permit()?;
        r.at_startup(&p);

        let why = r
            .on_unexplained_stream(&p, relay_ip()?, 30000)
            .err()
            .ok_or("a relay that is down attributes nothing")?;

        assert!(
            matches!(why, Unattributed::AskFailed { .. }),
            "a relay that could not be reached must report AskFailed, not \
             {why:?} -- an operator reading `does not hold this port` would \
             conclude the stream is not the relay's media, which nothing here \
             established"
        );
        Ok(())
    }

    /// The relay answered `list`, but the `query` for that call failed. Its
    /// ports are UNKNOWN, not absent.
    #[test]
    fn a_call_that_could_not_be_read_leaves_its_ports_unknown() -> Result<(), TestError> {
        let relay =
            ScriptedRelay::new(Answer::Calls(vec!["call-a"], false)).holding("call-a", None);
        let mut r = Reconciler::new(relay);
        let p = permit()?;
        r.at_startup(&p);

        let why = r
            .on_unexplained_stream(&p, relay_ip()?, 30000)
            .err()
            .ok_or("an unreadable call attributes nothing")?;

        assert!(
            !matches!(why, Unattributed::RelayDoesNotHoldIt),
            "a port may belong to the call whose query failed, so the answer \
             must not be `the relay does not hold it` -- got {why:?}"
        );
        Ok(())
    }

    /// The honest "no" must remain REACHABLE. Without this, every test above
    /// would still pass if `why_not` simply never returned
    /// [`Unattributed::RelayDoesNotHoldIt`] -- and sipnab would have traded a
    /// false denial for a permanent shrug.
    #[test]
    fn a_complete_answer_can_still_say_the_relay_does_not_hold_it() -> Result<(), TestError> {
        let relay = ScriptedRelay::new(Answer::Calls(vec!["call-a"], false))
            .holding("call-a", Some(vec![30000, 30001]));
        let mut r = Reconciler::new(relay);
        let p = permit()?;
        r.at_startup(&p);

        let why = r
            .on_unexplained_stream(&p, relay_ip()?, 40000)
            .err()
            .ok_or("40000 is not a port the relay named")?;

        assert_eq!(
            why,
            Unattributed::RelayDoesNotHoldIt,
            "the relay was reached, enumerated completely and every call was \
             read -- that is the one case where `not mine` is a fact"
        );
        Ok(())
    }

    /// One port number on two interfaces is two sockets. rtpengine allocates
    /// from a single port range across every `--interface`, so this is not a
    /// contrived case -- and keying the index on the port alone attributes one
    /// interface's media to the other interface's call.
    #[test]
    fn the_same_port_on_two_interfaces_is_two_different_calls() -> Result<(), TestError> {
        let relay = ScriptedRelay::new(Answer::Calls(vec!["call-a", "call-b"], false))
            .holding_on("call-a", "203.0.113.7", vec![30000])
            .holding_on("call-b", "198.51.100.9", vec![30000]);
        let mut r = Reconciler::new(relay);
        let p = permit()?;
        r.at_startup(&p);

        let first = "203.0.113.7"
            .parse()
            .map_err(|e| format!("a literal v4 address parses: {e:?}"))?;
        let second = "198.51.100.9"
            .parse()
            .map_err(|e| format!("a literal v4 address parses: {e:?}"))?;

        assert_eq!(
            r.on_unexplained_stream(&p, first, 30000)
                .map_err(|e| format!("the relay holds this socket: {e:?}"))?
                .call_id,
            "call-a"
        );
        assert_eq!(
            r.on_unexplained_stream(&p, second, 30000)
                .map_err(|e| format!("the relay holds this socket too: {e:?}"))?
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
        Ok(())
    }

    /// What the relay already said is not said again. Re-handing the startup
    /// snapshot would re-stamp every endpoint with a fresh time, and the
    /// store measures its staleness bound from that stamp -- so a replayed
    /// index would make every endpoint look perpetually current.
    #[test]
    fn a_socket_already_handed_over_is_not_handed_over_twice() -> Result<(), TestError> {
        let relay = ScriptedRelay::new(Answer::Calls(vec!["call-a"], false))
            .holding("call-a", Some(vec![30000, 30001]));
        let mut r = Reconciler::new(relay);
        let p = permit()?;
        r.at_startup(&p);

        let t0 = chrono::DateTime::from_timestamp(1_700_000_000, 0).ok_or("valid")?;
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
        Ok(())
    }

    /// A refresh hands over only what IT learned, stamped with when the relay
    /// answered rather than when a store happened to be written to.
    #[test]
    fn a_refresh_hands_over_only_what_it_learned() -> Result<(), TestError> {
        let relay = ScriptedRelay::new(Answer::Calls(vec!["call-a"], false))
            .holding("call-a", Some(vec![30000]))
            .failing_first(1);
        let mut r = Reconciler::new(relay);
        let p = permit()?;
        r.at_startup(&p);

        let t0 = chrono::DateTime::from_timestamp(1_700_000_000, 0).ok_or("valid")?;
        assert!(
            r.take_new_links(t0).links.is_empty(),
            "the startup query failed, so nothing was learned"
        );

        // The refresh retries the call and this time it answers.
        assert!(r.on_unexplained_stream(&p, relay_ip()?, 30000).is_ok());

        let t1 = chrono::DateTime::from_timestamp(1_700_000_060, 0).ok_or("valid")?;
        let handed = r.take_new_links(t1);
        assert_eq!(handed.links.len(), 1);
        assert_eq!(handed.links[0].port, 30000);
        assert_eq!(
            handed.taken_at,
            Some(t1),
            "stamped with the refresh, not with the startup that learned nothing"
        );
        Ok(())
    }

    /// Startup happens once. There is no second startup.
    #[test]
    fn startup_asks_once_and_never_again() -> Result<(), TestError> {
        let relay = ScriptedRelay::new(Answer::Calls(vec!["call-a"], false))
            .holding("call-a", Some(vec![30000]));
        let mut r = Reconciler::new(relay);
        let p = permit()?;

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
        Ok(())
    }

    /// The not-a-poller proof, stated as a number: a port the snapshot already
    /// explains costs NO control traffic, however often it is seen.
    #[test]
    fn an_explained_port_costs_no_control_traffic() -> Result<(), TestError> {
        let relay = ScriptedRelay::new(Answer::Calls(vec!["call-a"], false))
            .holding("call-a", Some(vec![30000]));
        let mut r = Reconciler::new(relay);
        let p = permit()?;
        r.at_startup(&p);
        let after_startup = r.transactions();

        for _ in 0..1000 {
            assert!(
                r.on_unexplained_stream(&p, relay_ip()?, 30000).is_ok(),
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
        Ok(())
    }

    /// An UNEXPLAINED port is asked about once for the run, not once per
    /// packet. This is the arm that would turn a busy capture into a flood.
    #[test]
    fn an_unexplained_port_is_asked_about_once() -> Result<(), TestError> {
        let relay = ScriptedRelay::new(Answer::Calls(vec!["call-a"], false))
            .holding("call-a", Some(vec![30000]));
        let mut r = Reconciler::new(relay);
        let p = permit()?;
        r.at_startup(&p);
        let after_startup = r.transactions();

        for _ in 0..500 {
            assert!(r.on_unexplained_stream(&p, relay_ip()?, 40000).is_err());
        }

        assert_eq!(
            r.transactions() - after_startup,
            1,
            "500 sightings of one unexplained port must cost a single refresh"
        );
        Ok(())
    }

    /// The ceiling does not depend on the traffic. A capture full of distinct
    /// orphan ports cannot buy more control transactions than the run allows.
    #[test]
    fn the_ceiling_bounds_the_run_whatever_the_traffic() -> Result<(), TestError> {
        let relay = ScriptedRelay::new(Answer::Calls(vec!["call-a"], false))
            .holding("call-a", Some(vec![30000]));
        let mut r = Reconciler::new(relay).with_budget(5);
        let p = permit()?;
        r.at_startup(&p);

        let mut last = None;
        for port in 40000..40200_u16 {
            last = Some(
                r.on_unexplained_stream(&p, relay_ip()?, port)
                    .err()
                    .ok_or("expected an error, got Ok")?,
            );
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
        Ok(())
    }

    /// A capped list is not a complete one, and a port missing from it proves
    /// nothing.
    #[test]
    fn a_truncated_enumeration_is_not_an_empty_one() -> Result<(), TestError> {
        let relay = ScriptedRelay::new(Answer::Calls(vec!["call-a"], true))
            .holding("call-a", Some(vec![30000]));
        let mut r = Reconciler::new(relay);
        let p = permit()?;
        r.at_startup(&p);

        assert!(r.enumeration_was_partial(), "the relay said it had more");
        assert_eq!(
            r.on_unexplained_stream(&p, relay_ip()?, 40000)
                .err()
                .ok_or("expected an error, got Ok")?,
            Unattributed::EnumerationWasPartial,
            "a port absent from a PARTIAL list may belong to a call the list \
             never named"
        );
        Ok(())
    }

    /// A call whose query failed is retried on the next refresh. Writing it
    /// off for the run would make a transient relay hiccup permanent, and the
    /// budget -- not a one-shot latch -- is what bounds the retries.
    #[test]
    fn a_call_that_failed_once_is_retried_not_written_off() -> Result<(), TestError> {
        let relay = ScriptedRelay::new(Answer::Calls(vec!["call-a"], false))
            .holding("call-a", Some(vec![30000]))
            .failing_first(1);
        let mut r = Reconciler::new(relay);
        let p = permit()?;
        r.at_startup(&p);

        assert_eq!(
            r.attributed_ports(),
            0,
            "the first query failed, so nothing is attributed yet"
        );

        assert!(
            r.on_unexplained_stream(&p, relay_ip()?, 30000).is_ok(),
            "the refresh retries the call that failed, and this time it \
             answers -- a port the relay genuinely holds must not stay \
             unattributed because of one transient failure"
        );
        Ok(())
    }

    /// A relay that DECLINED the question was reached and understood it, but
    /// it still never said this port is unheld.
    #[test]
    fn a_refusal_is_not_an_empty_relay() -> Result<(), TestError> {
        let mut r = Reconciler::new(ScriptedRelay::new(Answer::Refuse("not authorized")));
        let p = permit()?;
        r.at_startup(&p);

        let why = r
            .on_unexplained_stream(&p, relay_ip()?, 30000)
            .err()
            .ok_or("a refusal attributes nothing")?;

        assert!(
            !matches!(why, Unattributed::RelayDoesNotHoldIt),
            "a refused enumeration establishes nothing about this port -- got {why:?}"
        );
        Ok(())
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
                    facts: Default::default(),
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
                    facts: Default::default(),
                });
            }
            Ok(ControlReply::Call(CallView {
                call_id: call_id.to_owned(),
                tags: vec![RelayTag {
                    tag: format!("tag-of-{call_id}"),
                    in_dialogue_with: Vec::new(),
                    media_subscriptions: Vec::new(),
                    codec: Some("PCMU".to_owned()),
                    streams,
                }],
            }))
        }

        fn describe(&self) -> String {
            format!("{RELAY_IP}:2223")
        }
        fn statistics(
            &self,
            _permit: &crate::security::transmit_guard::TransmitPermit,
        ) -> anyhow::Result<crate::relay::types::ControlReply> {
            // A double, and no test asks it for counters. Refusing is what a
            // relay without statistics support would do, so this is the honest
            // stand-in rather than a fabricated answer.
            anyhow::bail!("this double answers no statistics")
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
    fn a_reused_relay_port_is_reported_again_with_its_new_call() -> Result<(), TestError> {
        let p = permit()?;
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
        let _ = r.on_unexplained_stream(
            &p,
            "198.51.100.9"
                .parse()
                .map_err(|e| format!("valid: {e:?}"))?,
            41234,
        );

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
        Ok(())
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
    fn a_socket_repeated_within_one_call_is_reported_only_once() -> Result<(), TestError> {
        let p = permit()?;
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
        Ok(())
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
    fn a_port_reassigned_twice_is_handed_over_each_time() -> Result<(), TestError> {
        let p = permit()?;
        let mut r = Reconciler::new(ReassigningRelay::new(
            vec![vec!["call-A"], vec!["call-B"], vec!["call-C"]],
            vec![30000],
        ));
        let other: IpAddr = "198.51.100.9"
            .parse()
            .map_err(|e| format!("valid: {e:?}"))?;

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
        Ok(())
    }

    /// Two ports reassigned in ONE refresh are both handed over.
    ///
    /// The hand-over skips a socket already queued, and this proves the skip
    /// is per-socket rather than per-refresh: a guard written as "something
    /// changed, so push once" reports one of these and drops the other,
    /// leaving half the call's media on the ended call.
    #[test]
    fn two_ports_reassigned_in_one_refresh_are_both_handed_over() -> Result<(), TestError> {
        let p = permit()?;
        let mut r = Reconciler::new(ReassigningRelay::new(
            vec![vec!["call-A"], vec!["call-B"]],
            vec![30000, 30002],
        ));

        r.at_startup(&p);
        let _ = r.take_new_links(chrono::Utc::now());

        let _ = r.on_unexplained_stream(
            &p,
            "198.51.100.9"
                .parse()
                .map_err(|e| format!("valid: {e:?}"))?,
            41234,
        );

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
        Ok(())
    }

    /// Offer `n` distinct unexplained sockets to a relay that holds nothing.
    fn flood<R: ReadOnlyRelay>(
        r: &mut Reconciler<R>,
        p: &TransmitPermit,
        n: u16,
    ) -> Result<(), TestError> {
        let ip: IpAddr = "198.51.100.9"
            .parse()
            .map_err(|e| format!("valid: {e:?}"))?;
        for i in 0..n {
            let _ = r.on_unexplained_stream(p, ip, 40000 + i);
        }
        Ok(())
    }

    /// The set of sockets already asked about cannot outgrow the ceiling.
    ///
    /// It was recorded BEFORE the ceiling was consulted, so it kept growing by
    /// one entry per distinct socket long after the reconciler had stopped
    /// asking anyone anything -- a per-socket allocation, never released, for
    /// the life of the run. Every entry now costs a transaction, so the
    /// ceiling bounds the memory as well as the traffic.
    #[test]
    fn the_tracked_socket_set_cannot_outgrow_the_transaction_ceiling() -> Result<(), TestError> {
        let p = permit()?;
        let mut r =
            Reconciler::new(ScriptedRelay::new(Answer::Calls(vec![], false))).with_budget(3);
        r.at_startup(&p);
        flood(&mut r, &p, 200)?;

        assert!(
            r.tracked_sockets() <= r.budget() as usize,
            "tracking {} socket(s) against a ceiling of {} -- the set is \
             growing with the traffic",
            r.tracked_sockets(),
            r.budget()
        );
        Ok(())
    }

    /// ...and the size does not depend on how much traffic arrives.
    ///
    /// Two runs, the same relay and ceiling, an order of magnitude apart in
    /// offered sockets. A bound that is real answers the same both times; a
    /// bound that merely looks generous does not.
    #[test]
    fn the_tracked_set_is_the_same_size_however_many_sockets_arrive() -> Result<(), TestError> {
        let p = permit()?;
        let mut small =
            Reconciler::new(ScriptedRelay::new(Answer::Calls(vec![], false))).with_budget(3);
        small.at_startup(&p);
        flood(&mut small, &p, 50)?;

        let mut large =
            Reconciler::new(ScriptedRelay::new(Answer::Calls(vec![], false))).with_budget(3);
        large.at_startup(&p);
        flood(&mut large, &p, 500)?;

        assert_eq!(
            small.tracked_sockets(),
            large.tracked_sockets(),
            "10x the sockets must not mean more state"
        );
        Ok(())
    }

    /// While the ceiling has room, a repeated socket is still asked about once.
    ///
    /// The bound on the two above. Dropping the record entirely also keeps the
    /// set small -- and turns every packet from one unexplained stream back
    /// into a control transaction, which is the poller this module exists to
    /// prevent.
    #[test]
    fn a_repeated_socket_still_costs_one_transaction_while_the_ceiling_has_room()
    -> Result<(), TestError> {
        let p = permit()?;
        let mut r =
            Reconciler::new(ScriptedRelay::new(Answer::Calls(vec![], false))).with_budget(20);
        r.at_startup(&p);
        let before = r.transactions();

        let ip: IpAddr = "198.51.100.9"
            .parse()
            .map_err(|e| format!("valid: {e:?}"))?;
        for _ in 0..10 {
            let _ = r.on_unexplained_stream(&p, ip, 41234);
        }

        assert_eq!(
            r.transactions() - before,
            1,
            "ten offers of one socket must cost one ask, not ten"
        );
        assert_eq!(r.tracked_sockets(), 1, "and it is remembered exactly once");
        Ok(())
    }

    /// A socket refused for want of budget SAYS that, and does not claim the
    /// relay disowned it.
    ///
    /// The early return added for the bound sits in front of the answer, so it
    /// is the return most likely to start reporting the wrong reason -- and
    /// `RelayDoesNotHoldIt` is the one answer here that asserts something
    /// about the traffic rather than about sipnab.
    #[test]
    fn a_socket_never_asked_about_is_not_reported_as_disowned() -> Result<(), TestError> {
        let p = permit()?;
        let mut r =
            Reconciler::new(ScriptedRelay::new(Answer::Calls(vec![], false))).with_budget(2);
        r.at_startup(&p);
        flood(&mut r, &p, 20)?;

        let why = r
            .on_unexplained_stream(
                &p,
                "203.0.113.9".parse().map_err(|e| format!("valid: {e:?}"))?,
                45000,
            )
            .err()
            .ok_or("the ceiling is spent, so nothing was asked")?;
        assert_eq!(
            why,
            Unattributed::BudgetSpent,
            "a port nobody asked about is not a port the relay disowned"
        );
        Ok(())
    }

    /// A relay that caps a narrow `list` and answers a wide one in full.
    ///
    /// The two answers differ, which is the whole point: a test whose relay
    /// ignores the limit cannot tell a run that reached further from one that
    /// asked the same question twice.
    struct WideningRelay {
        /// Every Call-ID this relay holds.
        all: Vec<String>,
        /// Every limit `list` was asked for, in order.
        ///
        /// Shared with the test rather than owned, because the reconciler
        /// takes the relay by value and a counter it swallows cannot be read.
        limits: std::rc::Rc<RefCell<Vec<u32>>>,
        /// Refuse any `list` wider than the datagram-safe default, as a relay
        /// with no stream transport configured does.
        refuse_wide: bool,
        /// What to answer a wider `list` with instead, when set.
        wide_reply: Option<ControlReply>,
    }

    /// A widening relay and the log of every limit it is asked for.
    fn widening(n: usize) -> (WideningRelay, std::rc::Rc<RefCell<Vec<u32>>>) {
        let limits = std::rc::Rc::new(RefCell::new(Vec::new()));
        (
            WideningRelay {
                all: (0..n).map(|i| format!("call-{i:04}")).collect(),
                limits: std::rc::Rc::clone(&limits),
                refuse_wide: false,
                wide_reply: None,
            },
            limits,
        )
    }

    impl WideningRelay {
        fn refusing_wide(mut self) -> Self {
            self.refuse_wide = true;
            self
        }

        fn answering_wide(mut self, reply: ControlReply) -> Self {
            self.wide_reply = Some(reply);
            self
        }
    }

    impl ReadOnlyRelay for WideningRelay {
        fn list(&self, _permit: &TransmitPermit, limit: u32) -> anyhow::Result<ControlReply> {
            self.limits.borrow_mut().push(limit);
            if self.refuse_wide && limit > DEFAULT_LIST_LIMIT {
                anyhow::bail!("connection refused");
            }
            if let Some(reply) = &self.wide_reply
                && limit > DEFAULT_LIST_LIMIT
            {
                return Ok(reply.clone());
            }
            let call_ids: Vec<String> = self
                .all
                .iter()
                .take(limit as usize)
                .map(String::clone)
                .collect();
            let truncated = call_ids.len() as u32 >= limit && limit > 0;
            Ok(ControlReply::Calls(Enumeration {
                call_ids,
                truncated,
            }))
        }

        fn query(&self, _permit: &TransmitPermit, call_id: &str) -> anyhow::Result<ControlReply> {
            let index = self
                .all
                .iter()
                .position(|c| c == call_id)
                .ok_or_else(|| anyhow::anyhow!("no such call"))?;
            Ok(ControlReply::Call(CallView {
                call_id: call_id.to_owned(),
                tags: vec![RelayTag {
                    tag: format!("tag-of-{call_id}"),
                    in_dialogue_with: Vec::new(),
                    media_subscriptions: Vec::new(),
                    codec: Some("PCMU".to_owned()),
                    streams: vec![RelayStream {
                        local_address: RELAY_IP.to_owned(),
                        local_port: 30000
                            + u16::try_from(index)
                                .map_err(|e| anyhow::anyhow!("a small index: {e}"))?,
                        endpoint: None,
                        advertised_endpoint: None,
                        is_rtcp: false,
                        ssrcs: Vec::new(),
                        facts: Default::default(),
                    }],
                }],
            }))
        }

        fn describe(&self) -> String {
            format!("{RELAY_IP}:22222")
        }
        fn statistics(
            &self,
            _permit: &crate::security::transmit_guard::TransmitPermit,
        ) -> anyhow::Result<crate::relay::types::ControlReply> {
            // A double, and no test asks it for counters. Refusing is what a
            // relay without statistics support would do, so this is the honest
            // stand-in rather than a fabricated answer.
            anyhow::bail!("this double answers no statistics")
        }
    }

    /// A capped enumeration is asked again for more than a datagram carries.
    ///
    /// The reach half of RE4. Measured against rtpengine 14.2.0.0 holding
    /// 1200 calls: `list` with `limit: 1200` produces a 73234-byte answer,
    /// which no UDP datagram can carry -- the request simply never gets a
    /// reply -- and the same request over a stream transport returns all 1200.
    /// Stopping at the first capped answer is what reports the rest as
    /// orphans.
    #[test]
    fn a_capped_enumeration_is_asked_again_for_more_than_a_datagram_carries()
    -> Result<(), TestError> {
        let (relay, limits) = widening(40);
        let mut r = Reconciler::new(relay).with_budget(200);
        let line = r.at_startup(&permit()?).ok_or("startup asks once")?;

        assert_eq!(
            *limits.borrow(),
            vec![DEFAULT_LIST_LIMIT, WIDE_LIST_LIMIT],
            "a capped answer must be followed by ONE wider ask; \
             the summary was: {line}"
        );
        assert!(
            line.contains("40 call(s) enumerated, complete"),
            "the wider answer is the one reported, not the capped one: {line}"
        );
        assert!(
            !r.enumeration_was_partial(),
            "the wider answer was complete, so nothing may still read as partial"
        );
        Ok(())
    }

    /// A relay with no wider transport keeps its capped answer, and the run
    /// SAYS the wider attempt was made and failed.
    ///
    /// "We never tried" and "we tried and could not" are different facts about
    /// the same missing calls, and only one of them tells the operator to go
    /// and enable something.
    #[test]
    fn a_wider_enumeration_that_fails_keeps_the_capped_answer_and_says_so() -> Result<(), TestError>
    {
        let (relay, _limits) = widening(40);
        let mut r = Reconciler::new(relay.refusing_wide()).with_budget(200);
        let line = r.at_startup(&permit()?).ok_or("startup asks once")?;

        assert!(
            r.enumeration_was_partial(),
            "the capped answer is still all there is, so this stays partial: {line}"
        );
        assert!(
            line.contains("connection refused"),
            "the operator must be told WHY the wider ask failed: {line}"
        );
        assert!(
            line.contains("32 call(s) enumerated"),
            "the capped answer must still be reported and used: {line}"
        );
        assert_eq!(
            r.attributed_ports(),
            32,
            "the calls the capped answer DID name must still be read"
        );
        Ok(())
    }

    /// The wider ask is spent once for the run, not once per refresh.
    #[test]
    fn a_wider_enumeration_is_attempted_once_for_the_run() -> Result<(), TestError> {
        let p = permit()?;
        let (relay, limits) = widening(40);
        let mut r = Reconciler::new(relay.refusing_wide()).with_budget(200);
        r.at_startup(&p);
        // A socket the snapshot does not hold forces a refresh.
        let _ = r.on_unexplained_stream(&p, relay_ip()?, 49999);

        let wide = limits
            .borrow()
            .iter()
            .filter(|l| **l == WIDE_LIST_LIMIT)
            .count();
        assert_eq!(
            wide,
            1,
            "a relay that cannot answer a wider `list` must be asked once, \
             not on every refresh: {:?}",
            limits.borrow()
        );
        Ok(())
    }

    /// A complete enumeration is never widened. Nothing is missing, so there
    /// is nothing to reach for and no packet to spend.
    #[test]
    fn a_complete_enumeration_is_never_widened() -> Result<(), TestError> {
        let (relay, limits) = widening(5);
        let mut r = Reconciler::new(relay).with_budget(200);
        r.at_startup(&permit()?);
        assert_eq!(
            *limits.borrow(),
            vec![DEFAULT_LIST_LIMIT],
            "the relay held five calls and answered completely; a second, \
             wider `list` is a packet sent to production for nothing"
        );
        Ok(())
    }

    /// Reaching further than the ceiling can read SAYS how many calls went
    /// unread.
    ///
    /// The reach half moves the binding constraint from the enumeration to the
    /// transaction ceiling. "400 enumerated, 64 queried" is arithmetic the
    /// operator should not have to do, and the calls in the gap are exactly
    /// the ones whose streams would otherwise look like orphans.
    #[test]
    fn calls_the_ceiling_could_not_read_are_counted_in_the_summary() -> Result<(), TestError> {
        let (relay, _limits) = widening(40);
        let mut r = Reconciler::new(relay).with_budget(12);
        let line = r.at_startup(&permit()?).ok_or("startup asks once")?;

        assert!(
            line.contains("30 call(s) were never read"),
            "the enumeration named 40 calls and the ceiling paid for ten \
             queries; the other thirty have to be named: {line}"
        );
        Ok(())
    }

    /// Every reason "nothing" can mean reads as its own sentence, and the two
    /// gaps say outright that they are not evidence the stream is unattached.
    /// The describe line is what an operator reads, so two reasons rendering
    /// alike would collapse exactly the distinction the enum exists to keep.
    #[test]
    fn every_reason_for_no_attribution_reads_as_its_own_sentence() -> Result<(), TestError> {
        let all = [
            Unattributed::RelayDoesNotHoldIt,
            Unattributed::EnumerationWasPartial,
            Unattributed::BudgetSpent,
            Unattributed::SnapshotIncomplete { unread_calls: 3 },
            Unattributed::AskFailed {
                reason: "connection refused".to_owned(),
            },
        ];
        let lines: Vec<String> = all.iter().map(Unattributed::describe).collect();
        let distinct: HashSet<&String> = lines.iter().collect();
        assert_eq!(distinct.len(), lines.len(), "reasons collide: {lines:?}");

        assert!(lines[0].contains("does not hold this port"), "{}", lines[0]);
        assert!(lines[1].contains("PARTIAL list of calls"), "{}", lines[1]);
        assert!(lines[2].contains("was not asked about"), "{}", lines[2]);
        assert!(
            lines[3].contains("named 3 call(s) that could not be read"),
            "the count of unread calls belongs in the sentence: {}",
            lines[3]
        );
        assert!(
            lines[4].contains("(connection refused)"),
            "the failure must be quoted: {}",
            lines[4]
        );
        for gap in [&lines[1], &lines[3]] {
            assert!(
                gap.contains("not evidence the stream is unattached"),
                "a gap must say it is not a denial: {gap}"
            );
        }
        assert!(
            !lines[0].contains("not evidence"),
            "the one real answer must not hedge: {}",
            lines[0]
        );
        Ok(())
    }

    /// A call whose query failed leaves the port UNKNOWN, and says how many
    /// calls are in that state -- the number an operator needs to judge how
    /// big the hole is.
    #[test]
    fn an_unreadable_call_is_reported_as_an_incomplete_snapshot_with_its_count()
    -> Result<(), TestError> {
        let relay = ScriptedRelay::new(Answer::Calls(vec!["call-a", "call-b"], false))
            .holding("call-a", None)
            .holding("call-b", None);
        let mut r = Reconciler::new(relay);
        let p = permit()?;
        let summary = r.at_startup(&p).ok_or("startup asks once")?;
        assert!(
            summary.contains("2 call(s) could not be read"),
            "the summary names the unread calls: {summary}"
        );

        assert_eq!(
            r.on_unexplained_stream(&p, relay_ip()?, 30000),
            Err(Unattributed::SnapshotIncomplete { unread_calls: 2 })
        );
        Ok(())
    }

    /// A relay with no per-call statistics form refuses the question rather
    /// than inventing an answer; the implementations that can answer override
    /// the default.
    #[test]
    fn a_relay_without_a_per_call_form_refuses_per_call_statistics() -> Result<(), TestError> {
        let relay = ScriptedRelay::new(Answer::Calls(vec![], false));
        let err = relay
            .call_statistics(&permit()?, "call-a")
            .err()
            .ok_or("the default has no per-call form")?;
        assert!(
            err.to_string().contains("no per-call statistics form"),
            "{err}"
        );
        Ok(())
    }

    /// The enumeration limit is what the relay is asked for, and a capped
    /// answer at a custom limit is still reached past.
    #[test]
    fn with_list_limit_is_the_limit_the_relay_is_asked_for() -> Result<(), TestError> {
        let (relay, limits) = widening(3);
        let mut r = Reconciler::new(relay).with_list_limit(5).with_budget(50);
        r.at_startup(&permit()?);
        assert_eq!(*limits.borrow(), vec![5], "three calls fit under five");

        let (relay, limits) = widening(8);
        let mut r = Reconciler::new(relay).with_list_limit(5).with_budget(50);
        r.at_startup(&permit()?);
        assert_eq!(
            *limits.borrow(),
            vec![5, WIDE_LIST_LIMIT],
            "a capped answer at five is followed by the one wider ask"
        );
        Ok(())
    }

    /// A limit already as wide as the reach is never "widened": the second
    /// ask would be the same question, and a packet spent for nothing.
    #[test]
    fn a_limit_already_at_the_wide_ceiling_is_not_asked_again() -> Result<(), TestError> {
        let (relay, limits) = widening(usize::from(u16::MAX) / 60);
        let mut r = Reconciler::new(relay)
            .with_list_limit(WIDE_LIST_LIMIT)
            .with_budget(3);
        let line = r.at_startup(&permit()?).ok_or("startup asks once")?;
        // 1092 calls against a limit of 1024: capped, and nothing wider to ask.
        assert_eq!(*limits.borrow(), vec![WIDE_LIST_LIMIT], "{line}");
        assert!(r.enumeration_was_partial());
        assert!(
            !line.contains("wider ask"),
            "no wider ask was made, so none may be reported: {line}"
        );
        Ok(())
    }

    /// The snapshot is every attributed socket, stamped with when the relay
    /// answered and which relay it was.
    #[test]
    fn the_snapshot_carries_every_attributed_socket_and_when_the_relay_answered()
    -> Result<(), TestError> {
        let relay = ScriptedRelay::new(Answer::Calls(vec!["call-a", "call-b"], false))
            .holding("call-a", Some(vec![30000, 30001]))
            .holding_on("call-b", "198.51.100.9", vec![40000]);
        let mut r = Reconciler::new(relay);
        r.at_startup(&permit()?);

        let mut links: Vec<(IpAddr, u16, String)> =
            r.links().map(|(a, p, c)| (a, p, c.to_owned())).collect();
        links.sort();
        let other: IpAddr = "198.51.100.9"
            .parse()
            .map_err(|e| format!("valid: {e:?}"))?;
        assert_eq!(
            links,
            vec![
                (other, 40000, "call-b".to_owned()),
                (relay_ip()?, 30000, "call-a".to_owned()),
                (relay_ip()?, 30001, "call-a".to_owned()),
            ]
        );

        let t0 = chrono::DateTime::from_timestamp(1_700_000_000, 0).ok_or("valid")?;
        let snap = r.snapshot(t0);
        assert_eq!(snap.taken_at, Some(t0));
        assert_eq!(
            snap.implementation,
            crate::relay::RelayImplementation::Rtpengine
        );
        let mut from_snapshot: Vec<(IpAddr, u16, String)> = snap
            .links
            .into_iter()
            .map(|l| (l.address, l.port, l.call_id))
            .collect();
        from_snapshot.sort();
        assert_eq!(from_snapshot, links, "the snapshot is the index, whole");

        assert_eq!(r.describe_relay(), "203.0.113.7:22222");
        Ok(())
    }

    /// A run whose ceiling is already spent asks nothing at startup and says
    /// so, rather than reporting an empty relay.
    #[test]
    fn a_run_with_no_ceiling_left_asks_nothing_and_says_so() -> Result<(), TestError> {
        let relay = ScriptedRelay::new(Answer::Calls(vec!["call-a"], false))
            .holding("call-a", Some(vec![30000]));
        let mut r = Reconciler::new(relay).with_budget(0);
        let line = r.at_startup(&permit()?).ok_or("startup still reports")?;

        assert_eq!(
            r.transactions(),
            0,
            "nothing may be spent past a zero ceiling"
        );
        assert!(
            line.starts_with("203.0.113.7:22222: not asked -- ")
                && line.contains("the control-transaction budget was empty"),
            "{line}"
        );
        assert_eq!(r.attributed_ports(), 0);
        Ok(())
    }

    /// A `list` answered with something that is not an enumeration is an ask
    /// that failed, not a relay holding nothing.
    #[test]
    fn a_list_answered_with_something_else_is_an_ask_failure_not_a_denial() -> Result<(), TestError>
    {
        let mut r = Reconciler::new(ScriptedRelay::new(Answer::NotAList));
        let p = permit()?;
        let line = r.at_startup(&p).ok_or("startup asks once")?;
        assert!(
            line.contains("answered a `list` with something else"),
            "{line}"
        );

        assert_eq!(
            r.on_unexplained_stream(&p, relay_ip()?, 30000),
            Err(Unattributed::AskFailed {
                reason: "the relay answered a `list` with something else".to_owned()
            })
        );
        Ok(())
    }

    /// A refusal names the relay's reason, both in the summary and in the
    /// answer a caller gets back.
    #[test]
    fn a_refused_enumeration_carries_the_relays_reason() -> Result<(), TestError> {
        let mut r = Reconciler::new(ScriptedRelay::new(Answer::Refuse("not authorized")));
        let p = permit()?;
        let line = r.at_startup(&p).ok_or("startup asks once")?;
        assert_eq!(
            line,
            "203.0.113.7:22222 refused to enumerate its calls: not authorized"
        );
        assert_eq!(
            r.on_unexplained_stream(&p, relay_ip()?, 30000),
            Err(Unattributed::AskFailed {
                reason: "the relay refused: not authorized".to_owned()
            })
        );
        Ok(())
    }

    /// A wider ask the relay REFUSED, or answered with something other than a
    /// list, keeps the capped answer and says why the reach failed.
    #[test]
    fn a_wider_ask_that_is_refused_or_misanswered_says_why() -> Result<(), TestError> {
        let cases = [
            (
                ControlReply::Refused {
                    reason: "limit too large".to_owned(),
                },
                "the relay refused: limit too large",
            ),
            (
                ControlReply::Statistics(Vec::new()),
                "the relay answered it with something else",
            ),
        ];
        for (reply, why) in cases {
            let (relay, _limits) = widening(40);
            let mut r = Reconciler::new(relay.answering_wide(reply)).with_budget(200);
            let line = r.at_startup(&permit()?).ok_or("startup asks once")?;
            assert!(
                line.contains(&format!("was attempted and failed ({why})")),
                "{line}"
            );
            assert!(
                r.enumeration_was_partial(),
                "the capped answer stands: {line}"
            );
            assert_eq!(r.attributed_ports(), 32, "and its calls are still read");
        }
        Ok(())
    }

    /// A capped answer that used the last transaction cannot be reached past,
    /// and the summary says both that the reach failed for want of budget and
    /// that the ceiling is now spent.
    #[test]
    fn a_capped_answer_on_the_last_transaction_says_the_reach_had_no_budget()
    -> Result<(), TestError> {
        let (relay, limits) = widening(40);
        let mut r = Reconciler::new(relay).with_budget(1);
        let line = r.at_startup(&permit()?).ok_or("startup asks once")?;

        assert_eq!(
            *limits.borrow(),
            vec![DEFAULT_LIST_LIMIT],
            "no second packet"
        );
        assert!(
            line.contains("failed (the control-transaction budget was already empty)"),
            "{line}"
        );
        assert!(
            line.contains("32 call(s) were never read"),
            "the calls the ceiling could not pay for are named: {line}"
        );
        assert!(
            line.ends_with("so a stream that turns up later is asked about once it has"),
            "{line}"
        );
        Ok(())
    }

    /// A relay stream whose address is not an IP address cannot be keyed. It
    /// is counted and SAID, rather than the port silently never attributing.
    #[test]
    fn a_relay_stream_that_names_no_ip_address_is_counted_and_said() -> Result<(), TestError> {
        let relay = ScriptedRelay::new(Answer::Calls(vec!["call-a", "call-b"], false))
            .holding("call-a", Some(vec![30000]))
            .holding_on("call-b", "relay-interface-0", vec![30002, 30004]);
        let mut r = Reconciler::new(relay);
        let line = r.at_startup(&permit()?).ok_or("startup asks once")?;

        assert_eq!(
            r.attributed_ports(),
            1,
            "only the keyable socket is indexed"
        );
        assert!(
            line.contains(
                "2 relay stream(s) reported an address that is not an IP address and could \
                 not be keyed"
            ),
            "{line}"
        );
        Ok(())
    }

    /// The refresh that spends the LAST transaction still read a complete
    /// answer, and that answer can still say "not mine".
    ///
    /// `why_not` checked the ceiling before anything else, so the socket whose
    /// own refresh used the final transaction was told the ceiling "was
    /// reached, so this port was never asked about" -- about a port that had
    /// just been asked about and disowned. The honest "no" has to stay
    /// reachable, and a sentence claiming no question was asked is false.
    #[test]
    fn the_refresh_that_spends_the_last_transaction_can_still_say_not_mine() -> Result<(), TestError>
    {
        let relay = ScriptedRelay::new(Answer::Calls(vec!["call-a"], false))
            .holding("call-a", Some(vec![30000]));
        let mut r = Reconciler::new(relay).with_budget(3);
        let p = permit()?;
        r.at_startup(&p);
        assert_eq!(r.transactions(), 2, "startup: one list, one query");

        let why = r
            .on_unexplained_stream(&p, relay_ip()?, 40000)
            .err()
            .ok_or("40000 is not a port the relay named")?;
        assert_eq!(
            r.transactions(),
            3,
            "the refresh spent the last transaction"
        );
        assert_eq!(
            why,
            Unattributed::RelayDoesNotHoldIt,
            "this port WAS asked about, and the complete answer disowned it"
        );

        assert_eq!(
            r.on_unexplained_stream(&p, relay_ip()?, 40001),
            Err(Unattributed::BudgetSpent),
            "the next port, which nothing could pay to ask about, was never asked"
        );
        Ok(())
    }

    /// ...and a refresh the ceiling cut SHORT stays a gap, never a denial.
    ///
    /// The bound on the case above. When the ceiling ran out before every
    /// enumerated call was read, the port may belong to one of the calls it
    /// never reached, and "the relay does not hold it" would be the false
    /// denial this module exists to prevent.
    #[test]
    fn a_refresh_the_ceiling_cut_short_is_still_a_gap() -> Result<(), TestError> {
        let mut r = Reconciler::new(ReassigningRelay::new(
            vec![vec![], vec!["call-A", "call-B"]],
            vec![30000],
        ))
        .with_budget(3);
        let p = permit()?;
        r.at_startup(&p);

        // The refresh lists two calls and can pay to read only one of them.
        let why = r
            .on_unexplained_stream(&p, relay_ip()?, 41234)
            .err()
            .ok_or("41234 is not call-A's port")?;
        assert_eq!(r.transactions(), 3);
        assert_eq!(
            why,
            Unattributed::BudgetSpent,
            "call-B was never read, so this port may be its: {why:?}"
        );
        Ok(())
    }

    // ── every listed engine ──────────────────────────────────────────

    /// Engine A holds call-a on 203.0.113.7 ports 30000-30001; engine B
    /// holds call-b on 203.0.113.8 ports 40000-40001, and also lists call-a,
    /// which it holds on port 40002.
    fn two_engines() -> Reconcilers<ScriptedRelay> {
        Reconcilers::new(vec![
            Reconciler::new(
                ScriptedRelay::new(Answer::Calls(vec!["call-a"], false))
                    .holding("call-a", Some(vec![30000, 30001]))
                    .named("engine at 192.0.2.5:2223"),
            ),
            Reconciler::new(
                ScriptedRelay::new(Answer::Calls(vec!["call-b", "call-a"], false))
                    .holding_on("call-b", "203.0.113.8", vec![40000, 40001])
                    .holding_on("call-a", "203.0.113.8", vec![40002])
                    .named("engine at 192.0.2.6:2223"),
            ),
        ])
    }

    /// Startup asks every engine: each engine's answer is a line of its own,
    /// a call two engines hold is named, and the snapshot carries every
    /// engine's sockets.
    #[test]
    fn startup_asks_every_engine_and_names_a_call_two_hold() -> Result<(), TestError> {
        let mut engines = two_engines();
        let lines = engines.at_startup(&permit()?);
        assert_eq!(
            lines.len(),
            3,
            "a line per engine, then the shared call: {lines:?}"
        );
        assert!(
            lines[0].starts_with("engine at 192.0.2.5:2223: "),
            "{lines:?}"
        );
        assert!(
            lines[1].starts_with("engine at 192.0.2.6:2223: "),
            "{lines:?}"
        );
        assert_eq!(
            lines[2], "Held by several engines: call-a",
            "the call two engines hold is named"
        );
        let mut links: Vec<(String, u16, String)> = engines
            .take_new_links(chrono::Utc::now())
            .links
            .into_iter()
            .map(|l| (l.address.to_string(), l.port, l.call_id))
            .collect();
        links.sort();
        assert_eq!(
            links,
            vec![
                ("203.0.113.7".to_string(), 30000, "call-a".to_string()),
                ("203.0.113.7".to_string(), 30001, "call-a".to_string()),
                ("203.0.113.8".to_string(), 40000, "call-b".to_string()),
                ("203.0.113.8".to_string(), 40001, "call-b".to_string()),
                ("203.0.113.8".to_string(), 40002, "call-a".to_string()),
            ],
            "every engine's sockets reach the snapshot"
        );
        assert!(
            engines.at_startup(&permit()?).is_empty(),
            "startup fires once"
        );
        Ok(())
    }

    /// An unexplained stream on a socket one engine already accounted for
    /// is attributed from memory, asking nothing. A socket no engine knows
    /// asks each engine in turn, until one attributes it.
    #[test]
    fn an_unexplained_stream_is_asked_of_each_engine_until_one_holds_it() -> Result<(), TestError> {
        let permit = permit()?;
        let mut engines = two_engines();
        let _ = engines.at_startup(&permit);
        let spent = |e: &Reconcilers<ScriptedRelay>| -> Vec<u32> {
            e.engines().iter().map(Reconciler::transactions).collect()
        };
        let before = spent(&engines);
        let known = engines
            .on_unexplained_stream(&permit, "203.0.113.8".parse()?, 40001)
            .found
            .ok_or("engine B accounted for it")?;
        assert_eq!(known.0, 1, "engine B accounted for it");
        assert_eq!(known.1.call_id, "call-b", "engine B accounted for it");
        assert_eq!(spent(&engines), before, "from memory, nothing asked");

        let unknown = engines.on_unexplained_stream(&permit, "203.0.113.9".parse()?, 50000);
        assert!(unknown.found.is_none(), "no engine holds it");
        let errs = unknown.why_not;
        assert_eq!(
            errs.iter().map(|(i, _)| *i).collect::<Vec<_>>(),
            vec![0, 1],
            "each engine was asked and said why not"
        );
        assert!(
            spent(&engines)
                .iter()
                .zip(&before)
                .all(|(now, was)| now > was),
            "each engine spent a refresh: {:?} after {before:?}",
            spent(&engines)
        );
        Ok(())
    }

    /// An engine that does not answer at startup says so in its own line,
    /// and the other engines' sockets are still learned.
    #[test]
    fn an_engine_that_is_down_does_not_hide_the_others() -> Result<(), TestError> {
        let mut engines = Reconcilers::new(vec![
            Reconciler::new(ScriptedRelay::new(Answer::Fail).named("engine at 192.0.2.5:2223")),
            Reconciler::new(
                ScriptedRelay::new(Answer::Calls(vec!["call-b"], false))
                    .holding_on("call-b", "203.0.113.8", vec![40000])
                    .named("engine at 192.0.2.6:2223"),
            ),
        ]);
        let lines = engines.at_startup(&permit()?);
        assert_eq!(lines.len(), 2, "no call two engines hold: {lines:?}");
        assert!(
            lines[0].contains("192.0.2.5:2223 could not be asked which calls are up"),
            "{lines:?}"
        );
        let links = engines.take_new_links(chrono::Utc::now()).links;
        assert_eq!(
            links.iter().map(|l| l.port).collect::<Vec<_>>(),
            vec![40000],
            "the answering engine's sockets are learned"
        );
        Ok(())
    }

    /// One engine reads exactly as the single reconciler did: one line, the
    /// same socket count, and errors from that engine alone.
    #[test]
    fn one_engine_reads_as_the_single_reconciler_did() -> Result<(), TestError> {
        let script = || {
            ScriptedRelay::new(Answer::Calls(vec!["call-a"], false))
                .holding("call-a", Some(vec![30000, 30001]))
        };
        let mut single = Reconciler::new(script());
        let mut engines = Reconcilers::new(vec![Reconciler::new(script())]);
        let want = single.at_startup(&permit()?).ok_or("a line")?;
        assert_eq!(engines.at_startup(&permit()?), vec![want], "the same line");
        assert_eq!(
            engines.take_new_links(chrono::Utc::now()).links.len(),
            single.take_new_links(chrono::Utc::now()).links.len(),
            "the same sockets"
        );
        Ok(())
    }

    // ── A budget that refills, and every engine asked at once ─────────

    /// A clock a test moves by hand, and the handle that moves it.
    fn test_clock() -> (Clock, Arc<std::sync::Mutex<std::time::Instant>>) {
        let now = Arc::new(std::sync::Mutex::new(std::time::Instant::now()));
        let read = Arc::clone(&now);
        let clock: Clock = Arc::new(move || {
            read.lock()
                .map(|t| *t)
                .unwrap_or_else(|_| std::time::Instant::now())
        });
        (clock, now)
    }

    /// Move a test clock forward.
    fn advance(
        now: &std::sync::Mutex<std::time::Instant>,
        by: std::time::Duration,
    ) -> Result<(), TestError> {
        let mut t = now.lock().map_err(|e| format!("clock lock: {e}"))?;
        *t = t
            .checked_add(by)
            .ok_or("the instant cannot be represented")?;
        Ok(())
    }

    /// Just over one token of the default refill (109.09 s).
    const ONE_TOKEN: std::time::Duration = std::time::Duration::from_secs(110);

    /// Short of one token of the default refill.
    const SHORT_OF_A_TOKEN: std::time::Duration = std::time::Duration::from_secs(100);

    /// A relay whose list a test changes between asks, holding each call on
    /// one port, or failing its query when the port is `None`.
    struct ChangingRelay {
        listed: RefCell<(Vec<&'static str>, bool)>,
        ports: HashMap<&'static str, Option<u16>>,
        lists: RefCell<u32>,
    }

    impl ChangingRelay {
        fn new(listed: &[&'static str], ports: &[(&'static str, Option<u16>)]) -> Self {
            Self {
                listed: RefCell::new((listed.to_vec(), false)),
                ports: ports.iter().copied().collect(),
                lists: RefCell::new(0),
            }
        }

        fn list_now(&self, listed: &[&'static str], truncated: bool) {
            *self.listed.borrow_mut() = (listed.to_vec(), truncated);
        }
    }

    impl ReadOnlyRelay for ChangingRelay {
        fn list(&self, _: &TransmitPermit, _: u32) -> anyhow::Result<ControlReply> {
            *self.lists.borrow_mut() += 1;
            let (ids, truncated) = self.listed.borrow().clone();
            Ok(ControlReply::Calls(Enumeration {
                call_ids: ids.into_iter().map(str::to_owned).collect(),
                truncated,
            }))
        }

        fn query(&self, _: &TransmitPermit, call_id: &str) -> anyhow::Result<ControlReply> {
            let Some(Some(port)) = self.ports.get(call_id) else {
                anyhow::bail!("relay busy");
            };
            Ok(ControlReply::Call(CallView {
                call_id: call_id.to_owned(),
                tags: vec![RelayTag {
                    tag: "from-tag".to_owned(),
                    in_dialogue_with: Vec::new(),
                    media_subscriptions: Vec::new(),
                    codec: None,
                    streams: vec![RelayStream {
                        local_address: RELAY_IP.to_owned(),
                        local_port: *port,
                        endpoint: None,
                        advertised_endpoint: None,
                        is_rtcp: false,
                        ssrcs: Vec::new(),
                        facts: Default::default(),
                    }],
                }],
            }))
        }

        fn statistics(&self, _: &TransmitPermit) -> anyhow::Result<ControlReply> {
            anyhow::bail!("not scripted")
        }

        fn describe(&self) -> String {
            "engine at 192.0.2.5:2223".to_owned()
        }
    }

    /// An empty budget refills, and a stream that turns up once it has is
    /// asked about.
    #[test]
    fn a_spent_budget_refills_and_a_later_stream_is_asked() -> Result<(), TestError> {
        let (clock, now) = test_clock();
        let relay = ScriptedRelay::new(Answer::Calls(vec!["call-a"], false))
            .holding("call-a", Some(vec![30000]));
        let mut r = Reconciler::new(relay).with_clock(clock).with_budget(2);
        let _ = r.at_startup(&permit()?);
        assert_eq!(r.available(), 0, "startup spent the list and the query");
        advance(&now, ONE_TOKEN)?;
        let got = r.on_unexplained_stream(&permit()?, relay_ip()?, 40000);
        assert_eq!(*r.relay.lists.borrow(), 2, "asked once the budget refilled");
        assert_eq!(got, Err(Unattributed::RelayDoesNotHoldIt), "and answered");
        Ok(())
    }

    /// Short of the refill, a stream is still not asked about.
    #[test]
    fn short_of_the_refill_a_stream_is_not_asked() -> Result<(), TestError> {
        let (clock, now) = test_clock();
        let relay = ScriptedRelay::new(Answer::Calls(vec!["call-a"], false))
            .holding("call-a", Some(vec![30000]));
        let mut r = Reconciler::new(relay).with_clock(clock).with_budget(2);
        let _ = r.at_startup(&permit()?);
        advance(&now, SHORT_OF_A_TOKEN)?;
        assert_eq!(
            r.on_unexplained_stream(&permit()?, relay_ip()?, 40000),
            Err(Unattributed::BudgetSpent),
            "short of the refill the budget is still empty",
        );
        assert_eq!(*r.relay.lists.borrow(), 1, "nothing asked while empty");
        Ok(())
    }

    /// A call the engine set up after the budget ran out is named once the
    /// budget has refilled: a list and a query.
    #[test]
    fn a_call_set_up_later_is_named_after_the_refill() -> Result<(), TestError> {
        let (clock, now) = test_clock();
        let relay = ChangingRelay::new(&["a"], &[("a", Some(30000)), ("b", Some(30002))]);
        let mut r = Reconciler::new(relay).with_clock(clock).with_budget(2);
        let _ = r.at_startup(&permit()?);
        r.relay.list_now(&["a", "b"], false);
        advance(&now, ONE_TOKEN * 2)?;
        let got = r
            .on_unexplained_stream(&permit()?, relay_ip()?, 30002)
            .map(|a| a.call_id);
        assert_eq!(
            got,
            Ok("b".to_owned()),
            "the later call is named once two tokens refilled"
        );
        Ok(())
    }

    /// The refresh that empties the budget says how it refills.
    #[test]
    fn the_line_that_empties_the_budget_says_how_it_refills() -> Result<(), TestError> {
        let relay = ScriptedRelay::new(Answer::Calls(vec!["call-a"], false))
            .holding("call-a", Some(vec![30000]));
        let mut r = Reconciler::new(relay).with_budget(2);
        let line = r.at_startup(&permit()?).ok_or("a line")?;
        assert!(
            line.ends_with(
                ". The control-transaction budget is now empty; it refills at 33 \
                 per hour, up to 2, so a stream that turns up later is asked about \
                 once it has"
            ),
            "{line}"
        );
        Ok(())
    }

    /// With no refill, the line says the ceiling for the run is spent, as it
    /// did before the budget refilled.
    #[test]
    fn with_no_refill_the_line_says_the_run_is_spent() -> Result<(), TestError> {
        let relay = ScriptedRelay::new(Answer::Calls(vec!["call-a"], false))
            .holding("call-a", Some(vec![30000]));
        let mut r = Reconciler::new(relay).with_budget(2).with_refill(None);
        let line = r.at_startup(&permit()?).ok_or("a line")?;
        assert!(
            line.ends_with(
                ". The control-transaction ceiling for this run is now spent, so \
                 no further questions will be asked"
            ),
            "{line}"
        );
        Ok(())
    }

    /// The reconciler says what it holds and how long until the next
    /// transaction.
    #[test]
    fn the_reconciler_says_what_is_left_and_when_more_comes() -> Result<(), TestError> {
        let (clock, now) = test_clock();
        let relay = ScriptedRelay::new(Answer::Calls(vec![], false));
        let mut r = Reconciler::new(relay).with_clock(clock).with_budget(1);
        assert_eq!((r.available(), r.next_refill_in()), (1, None), "full");
        let _ = r.at_startup(&permit()?);
        let wait = r.next_refill_in().ok_or("empty, so a wait")?;
        assert!(
            wait > SHORT_OF_A_TOKEN && wait <= ONE_TOKEN,
            "one token's time: {wait:?}"
        );
        advance(&now, ONE_TOKEN)?;
        assert_eq!(r.available(), 1, "refilled");
        assert_eq!(
            r.refill(),
            Some(super::super::budget::DEFAULT_REFILL),
            "the default refill is reported"
        );
        Ok(())
    }

    /// The asked-about sockets remembered never pass the memory's size,
    /// however many are asked about.
    #[test]
    fn the_remembered_sockets_are_capped() -> Result<(), TestError> {
        let relay = ScriptedRelay::new(Answer::Calls(vec![], false));
        let mut r = Reconciler::new(relay)
            .with_budget(100)
            .with_socket_memory(4);
        for port in 1..=10 {
            let _ = r.on_unexplained_stream(&permit()?, relay_ip()?, port);
        }
        assert_eq!(
            r.tracked_sockets(),
            4,
            "the memory holds four sockets however many were asked about"
        );
        assert_eq!(
            *r.relay.lists.borrow(),
            10,
            "each new socket was asked about"
        );
        Ok(())
    }

    /// The oldest socket is the one forgotten: asked about again, it spends a
    /// transaction, and a socket still remembered does not.
    #[test]
    fn a_forgotten_socket_is_asked_again_and_spends() -> Result<(), TestError> {
        let relay = ScriptedRelay::new(Answer::Calls(vec![], false));
        let mut r = Reconciler::new(relay)
            .with_budget(100)
            .with_socket_memory(2);
        for port in [1, 2, 3] {
            let _ = r.on_unexplained_stream(&permit()?, relay_ip()?, port);
        }
        let _ = r.on_unexplained_stream(&permit()?, relay_ip()?, 3);
        assert_eq!(*r.relay.lists.borrow(), 3, "3 is remembered");
        let _ = r.on_unexplained_stream(&permit()?, relay_ip()?, 1);
        assert_eq!(
            *r.relay.lists.borrow(),
            4,
            "1 was forgotten and asked again"
        );
        assert_eq!(
            r.transactions(),
            4,
            "four transactions: three sockets and one forgotten one asked again"
        );
        Ok(())
    }

    /// A complete list that no longer names a call forgets it and its
    /// sockets: the index holds what the engine holds, not every call the run
    /// ever saw.
    #[test]
    fn a_complete_list_forgets_ended_calls() -> Result<(), TestError> {
        let relay = ChangingRelay::new(&["a", "b"], &[("a", Some(30000)), ("b", Some(30002))]);
        let mut r = Reconciler::new(relay);
        let _ = r.at_startup(&permit()?);
        assert_eq!(r.attributed_ports(), 2, "both calls attributed at startup");
        r.relay.list_now(&["b"], false);
        let _ = r.on_unexplained_stream(&permit()?, relay_ip()?, 39998);
        let ports: Vec<u16> = r.links().map(|(_, p, _)| p).collect();
        assert_eq!(ports, vec![30002], "a ended and is forgotten");
        Ok(())
    }

    /// A capped list says nothing about the calls past the cap, so it forgets
    /// nothing.
    #[test]
    fn a_capped_list_forgets_nothing() -> Result<(), TestError> {
        let relay = ChangingRelay::new(&["a", "b"], &[("a", Some(30000)), ("b", Some(30002))]);
        let mut r = Reconciler::new(relay);
        let _ = r.at_startup(&permit()?);
        r.relay.list_now(&["b"], true);
        let _ = r.on_unexplained_stream(&permit()?, relay_ip()?, 39998);
        assert_eq!(r.attributed_ports(), 2, "a may be past the cap");
        Ok(())
    }

    /// A call that could not be read and has since ended no longer makes the
    /// snapshot incomplete.
    #[test]
    fn an_unread_call_that_ended_stops_counting_as_unread() -> Result<(), TestError> {
        let relay = ChangingRelay::new(&["a", "c"], &[("a", Some(30000)), ("c", None)]);
        let mut r = Reconciler::new(relay);
        let _ = r.at_startup(&permit()?);
        r.relay.list_now(&["a"], false);
        assert_eq!(
            r.on_unexplained_stream(&permit()?, relay_ip()?, 39998),
            Err(Unattributed::RelayDoesNotHoldIt),
            "c ended, so its unread state no longer governs"
        );
        Ok(())
    }

    /// One engine's empty budget leaves the other engines theirs: each
    /// engine keeps its own ceiling, asked at once.
    #[test]
    fn one_engines_empty_budget_leaves_the_others_theirs() -> Result<(), TestError> {
        let mut engines = Reconcilers::new(vec![
            Reconciler::new(
                ScriptedRelay::new(Answer::Calls(vec!["call-a"], false))
                    .holding("call-a", Some(vec![30000]))
                    .named("engine at 192.0.2.5:2223"),
            )
            .with_budget(1),
            Reconciler::new(
                ScriptedRelay::new(Answer::Calls(vec!["call-b"], false))
                    .holding_on("call-b", "203.0.113.8", vec![40000])
                    .named("engine at 192.0.2.6:2223"),
            ),
        ]);
        let lines = engines.at_startup(&permit()?);
        assert!(
            lines[0].contains("1 call(s) were never read")
                && lines[0].contains("budget is now empty"),
            "{lines:?}"
        );
        assert!(lines[1].contains("queried 1 of them"), "{lines:?}");
        let spent: Vec<u32> = engines
            .engines()
            .iter()
            .map(Reconciler::transactions)
            .collect();
        assert_eq!(spent, vec![1, 2], "each within its own budget");
        Ok(())
    }

    /// A relay that answers its list only when every engine is being asked
    /// at the same moment.
    struct GateRelay {
        gate: Arc<crate::test_engines::Gate>,
        name: String,
    }

    impl ReadOnlyRelay for GateRelay {
        fn list(&self, _: &TransmitPermit, _: u32) -> anyhow::Result<ControlReply> {
            if !self.gate.arrive(std::time::Duration::from_secs(5)) {
                anyhow::bail!("asked alone");
            }
            Ok(ControlReply::Calls(Enumeration {
                call_ids: Vec::new(),
                truncated: false,
            }))
        }
        fn query(&self, _: &TransmitPermit, _: &str) -> anyhow::Result<ControlReply> {
            anyhow::bail!("not scripted")
        }
        fn statistics(&self, _: &TransmitPermit) -> anyhow::Result<ControlReply> {
            anyhow::bail!("not scripted")
        }
        fn describe(&self) -> String {
            self.name.clone()
        }
    }

    /// Startup asks every engine at the same time.
    #[test]
    fn startup_asks_every_engine_at_once() -> Result<(), TestError> {
        let gate = Arc::new(crate::test_engines::Gate::new(3));
        let mut engines = Reconcilers::new(
            (0..3)
                .map(|i| {
                    Reconciler::new(GateRelay {
                        gate: Arc::clone(&gate),
                        name: format!("engine {i}"),
                    })
                })
                .collect(),
        );
        let lines = engines.at_startup(&permit()?);
        assert!(
            lines.iter().all(|l| l.contains("enumerated")),
            "every engine was asked with the others: {lines:?}"
        );
        Ok(())
    }

    /// A relay that answers its list only after `after` other relays have
    /// answered theirs, and records that it did. The order is set by that
    /// event, not by a delay: delays of 150 ms apart set it before, and a
    /// loaded host can run them out of order.
    struct LateRelay {
        after: usize,
        name: String,
        answered: Arc<crate::test_engines::FinishOrder<String>>,
    }

    impl ReadOnlyRelay for LateRelay {
        fn list(&self, _: &TransmitPermit, _: u32) -> anyhow::Result<ControlReply> {
            let in_turn = self.answered.finish_after(
                self.after,
                self.name.clone(),
                std::time::Duration::from_secs(30),
            );
            anyhow::ensure!(in_turn, "{} gave up waiting for its turn", self.name);
            Ok(ControlReply::Calls(Enumeration {
                call_ids: Vec::new(),
                truncated: false,
            }))
        }
        fn query(&self, _: &TransmitPermit, _: &str) -> anyhow::Result<ControlReply> {
            anyhow::bail!("not scripted")
        }
        fn statistics(&self, _: &TransmitPermit) -> anyhow::Result<ControlReply> {
            anyhow::bail!("not scripted")
        }
        fn describe(&self) -> String {
            self.name.clone()
        }
    }

    /// Answers that arrive last engine first still print first engine first.
    #[test]
    fn startup_lines_keep_the_configured_order() -> Result<(), TestError> {
        let answered = Arc::new(crate::test_engines::FinishOrder::new());
        let mut engines = Reconcilers::new(
            (0..3_usize)
                .map(|i| {
                    Reconciler::new(LateRelay {
                        after: 2 - i,
                        name: format!("engine {i}"),
                        answered: Arc::clone(&answered),
                    })
                })
                .collect(),
        );
        let lines = engines.at_startup(&permit()?);
        let first_words: Vec<&str> = lines.iter().filter_map(|l| l.split(':').next()).collect();
        assert_eq!(
            first_words,
            vec!["engine 0", "engine 1", "engine 2"],
            "the lines are in the engines' order"
        );
        assert_eq!(
            answered.order(),
            vec!["engine 2", "engine 1", "engine 0"],
            "they answered in reverse"
        );
        assert!(
            lines.iter().all(|l| l.contains("enumerated")),
            "no engine gave up waiting for its turn: {lines:?}"
        );
        Ok(())
    }

    /// Startup with three dead engines and a live one costs one timeout, and
    /// every engine still gets its line, in order.
    #[test]
    fn startup_with_dead_engines_costs_one_timeout() -> Result<(), TestError> {
        use crate::test_engines::{FakeEngine, all_answered, waited_a_timeout};
        // Asked at once, not in turn: three engines that answer only when
        // all three hold a request. No wall time is read for it.
        let asked = FakeEngine::together_beside_a_live_one(4, 1)?;
        let lines = Reconcilers::new(
            asked
                .iter()
                .map(|f| Reconciler::new(f.control_client()))
                .collect(),
        )
        .at_startup(&permit()?);
        assert!(
            all_answered(&asked),
            "the engines were asked one after another: {lines:?}"
        );
        let fakes = [
            FakeEngine::dead()?,
            FakeEngine::live()?,
            FakeEngine::dead()?,
            FakeEngine::dead()?,
        ];
        let mut engines = Reconcilers::new(
            fakes
                .iter()
                .map(|f| Reconciler::new(f.control_client()))
                .collect(),
        );
        let started = std::time::Instant::now();
        let lines = engines.at_startup(&permit()?);
        let took = started.elapsed();
        assert!(
            waited_a_timeout(took),
            "the dead engines were waited for: {took:?}"
        );
        for (i, (line, fake)) in lines.iter().zip(&fakes).enumerate() {
            assert!(
                line.starts_with(&fake.describe()),
                "line {i} is engine {i}'s: {lines:?}"
            );
        }
        assert!(lines[1].contains("enumerated"), "{lines:?}");
        for i in [0, 2, 3] {
            assert!(lines[i].contains("could not be asked"), "{lines:?}");
        }
        Ok(())
    }

    /// With every engine dead, each says so, in order, after one timeout.
    #[test]
    fn startup_with_every_engine_dead_says_so_for_each() -> Result<(), TestError> {
        use crate::test_engines::{FakeEngine, waited_a_timeout};
        let fakes = [
            FakeEngine::dead()?,
            FakeEngine::dead()?,
            FakeEngine::dead()?,
        ];
        let mut engines = Reconcilers::new(
            fakes
                .iter()
                .map(|f| Reconciler::new(f.control_client()))
                .collect(),
        );
        let started = std::time::Instant::now();
        let lines = engines.at_startup(&permit()?);
        let took = started.elapsed();
        assert!(
            waited_a_timeout(took),
            "the dead engines were waited for: {took:?}"
        );
        let want: Vec<String> = fakes
            .iter()
            .map(|f| format!("{} could not be asked", f.describe()))
            .collect();
        let got: Vec<String> = lines
            .iter()
            .map(|l| {
                l.split(" which calls")
                    .next()
                    .unwrap_or_default()
                    .to_owned()
            })
            .collect();
        assert_eq!(got, want, "each dead engine's line, in the engines' order");
        Ok(())
    }

    /// Asked at once, each dead engine still gets exactly one request: no
    /// retry, and one socket per engine.
    #[test]
    fn startup_sends_each_dead_engine_one_request() -> Result<(), TestError> {
        use crate::test_engines::FakeEngine;
        let fakes = [FakeEngine::dead()?, FakeEngine::dead()?];
        let mut engines = Reconcilers::new(
            fakes
                .iter()
                .map(|f| Reconciler::new(f.control_client()))
                .collect(),
        );
        let _ = engines.at_startup(&permit()?);
        let seen: Vec<usize> = fakes.iter().map(FakeEngine::requests).collect();
        assert_eq!(seen, vec![1, 1], "one request per dead engine, no retry");
        Ok(())
    }
}
