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
//! - **A ceiling that does not depend on the traffic.** [`Reconciler::budget`]
//!   bounds transactions for the whole run. A capture full of orphans cannot
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

use std::collections::{HashMap, HashSet};

use super::control::{CallView, ControlReply, Enumeration};
use crate::security::transmit_guard::TransmitPermit;

/// Everything the reconciler is permitted to ask a relay.
///
/// Two methods. rtpengine's ng protocol also carries `offer`, `answer`,
/// `delete` and `start recording`, every one of which CHANGES a production
/// relay. None of them is reachable from here, and adding one would mean
/// adding a method to this trait -- a visible act in a diff rather than an
/// oversight in a call site.
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
/// datagram. [`Enumeration::truncated`] is what keeps a capped answer from
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
pub struct Reconciler<R: ReadOnlyRelay> {
    /// The relay, reachable only through the two read-only questions.
    relay: R,
    /// Startup fires once. There is no second startup.
    startup_done: bool,
    /// Relay-side port to what the relay said about it.
    index: HashMap<u16, Attribution>,
    /// Calls already queried, so a refresh asks only about new ones.
    known_calls: HashSet<String>,
    /// Ports already asked about, so an unexplained stream is asked about
    /// once rather than once per packet.
    asked_ports: HashSet<u16>,
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
            enumeration_partial: false,
            last_ask_failure: None,
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
        Some(self.snapshot(permit))
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
        local_port: u16,
    ) -> Result<Attribution, Unattributed> {
        if let Some(found) = self.index.get(&local_port) {
            return Ok(found.clone());
        }
        if !self.asked_ports.insert(local_port) {
            // Already asked about this port and the refresh did not find it.
            // Asking again would produce the same answer and one more packet.
            return Err(self.why_not(local_port));
        }
        // The snapshot did not contain it, so the snapshot is stale: a call
        // the relay set up after sipnab started. Refresh, asking only about
        // calls not already known.
        let _ = self.snapshot(permit);
        self.index
            .get(&local_port)
            .cloned()
            .ok_or_else(|| self.why_not(local_port))
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
    fn why_not(&self, _local_port: u16) -> Unattributed {
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
    fn snapshot(&mut self, permit: &TransmitPermit) -> String {
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
                self.index.insert(
                    stream.local_port,
                    Attribution {
                        call_id: view.call_id.clone(),
                        tag: tag.tag.clone(),
                        peer_tags: tag.in_dialogue_with.clone(),
                        is_rtcp: stream.is_rtcp,
                        codec: tag.codec.clone(),
                    },
                );
            }
        }
    }
}

/// A `list` answer with nothing in it, for callers that need one.
#[must_use]
pub fn empty_enumeration() -> Enumeration {
    Enumeration {
        call_ids: Vec::new(),
        truncated: false,
    }
}

/// The live client is the only production implementation.
///
/// The impl lives here rather than beside [`ControlClient`] so that the
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
mod tests {
    use super::*;
    use crate::capture::CaptureSource;
    use crate::rtpengine::control::{RelayStream, RelayTag};
    use std::cell::RefCell;

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
                fail_first: 0,
                lists: RefCell::new(0),
                queries: RefCell::new(Vec::new()),
            }
        }

        fn holding(mut self, call_id: &str, ports: Option<Vec<u16>>) -> Self {
            self.calls.insert(call_id.to_owned(), ports);
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
                Some(Some(ports)) => Ok(ControlReply::Call(CallView {
                    call_id: call_id.to_owned(),
                    tags: vec![RelayTag {
                        tag: "from-tag".to_owned(),
                        in_dialogue_with: vec!["to-tag".to_owned()],
                        codec: Some("PCMU".to_owned()),
                        streams: ports
                            .iter()
                            .map(|p| RelayStream {
                                local_address: "203.0.113.7".to_owned(),
                                local_port: *p,
                                endpoint: None,
                                advertised_endpoint: None,
                                is_rtcp: p % 2 == 1,
                                ssrcs: Vec::new(),
                            })
                            .collect(),
                    }],
                })),
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
            .on_unexplained_stream(&p, 30000)
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
            .on_unexplained_stream(&p, 30000)
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
            .on_unexplained_stream(&p, 40000)
            .expect_err("40000 is not a port the relay named");

        assert_eq!(
            why,
            Unattributed::RelayDoesNotHoldIt,
            "the relay was reached, enumerated completely and every call was \
             read -- that is the one case where `not mine` is a fact"
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
                r.on_unexplained_stream(&p, 30000).is_ok(),
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
            assert!(r.on_unexplained_stream(&p, 40000).is_err());
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
            last = Some(r.on_unexplained_stream(&p, port).unwrap_err());
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
            r.on_unexplained_stream(&p, 40000).unwrap_err(),
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
            r.on_unexplained_stream(&p, 30000).is_ok(),
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
            .on_unexplained_stream(&p, 30000)
            .expect_err("a refusal attributes nothing");

        assert!(
            !matches!(why, Unattributed::RelayDoesNotHoldIt),
            "a refused enumeration establishes nothing about this port -- got {why:?}"
        );
    }
}
