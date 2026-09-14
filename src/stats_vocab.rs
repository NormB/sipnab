// SPDX-License-Identifier: MIT OR Apache-2.0

//! The statistics vocabulary (ST1), portable the way [`crate::relay_vocab`] is.
//!
//! Every figure sipnab reports about media belongs to exactly one of three
//! tiers, and the tiers are not interchangeable. A statistics surface is where
//! an operator asks a question like "is the relay losing my audio", and three
//! different things in this program can answer it:
//!
//!  * the relay's own `rtpa_nlost`,
//!  * a count of sequence-number gaps in the RTP sipnab saw,
//!  * the far endpoint's `fraction lost` in an RTCP report.
//!
//! All three are "packet loss". None measures the same thing. A number shown
//! without its tier picks a winner silently; a number built by combining two
//! tiers describes nothing while looking authoritative. This module is the
//! vocabulary that keeps them apart, and the rule that forbids blending them.
//!
//! The contract here is `docs/design/relay-statistics-vocabulary.md` (ST-S1).
//! It lives beside [`crate::relay_vocab`] rather than in `crate::relay` because
//! two of its three tiers -- `sipnab_measured` and `endpoint_reported` -- are
//! not relay concepts at all, and the wasm analyzer reports `sipnab_measured`
//! figures with no control plane in sight. Words are portable even where the
//! machinery is not.

/// Which kind of claim a statistic is.
///
/// The wire names are `snake_case` and deliberately NOT hyphenated: they match
/// `endpoint_reported`, `xr_voip_metrics` and `sender_report_echo`, the names
/// consumers already parse. `crate::relay_vocab`'s `media-relay` keeps its
/// hyphen because it is a different, already-shipped field; this vocabulary is
/// new and chooses the convention its neighbors use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum StatisticTier {
    /// What rtpengine or rtpproxy says about ITSELF, obtained by asking it. A
    /// claim from a box that may have restarted, and whose control plane may or
    /// may not carry a credential.
    RelayReported,
    /// Computed from packets sipnab actually saw. Bounded by what reached the
    /// capture point, which is not the same as what happened.
    SipnabMeasured,
    /// Asserted by a remote endpoint in an RTCP SR, RR or XR. Evidence of what
    /// the far end claims, never a measurement, and never checkable.
    EndpointReported,
}

impl StatisticTier {
    /// The wire name, spelled once here and mapped nowhere else.
    ///
    /// One map, for the reason [`crate::rtp::rtcp::RttSource::as_wire_str`]
    /// gives: two surfaces each keeping their own is how one fact ships under
    /// two spellings to consumers meant to agree.
    #[must_use]
    pub const fn as_wire_str(self) -> &'static str {
        match self {
            Self::RelayReported => "relay_reported",
            Self::SipnabMeasured => "sipnab_measured",
            Self::EndpointReported => "endpoint_reported",
        }
    }

    /// Every tier, for a test that must cover all of them.
    #[must_use]
    pub const fn all() -> [Self; 3] {
        [
            Self::RelayReported,
            Self::SipnabMeasured,
            Self::EndpointReported,
        ]
    }
}

/// Whether combining a value of tier `a` with a value of tier `b` would BLEND
/// two tiers -- which is forbidden without exception (ST-S1).
///
/// True exactly when the tiers differ. A relay's packet count minus sipnab's
/// is not "packets sipnab missed": the two count different sockets over
/// different windows with different start times.
///
/// This is necessary, not sufficient, for a legal aggregate. Two figures of
/// the SAME tier from two different relays still must not be summed -- two
/// restart epochs -- but that is a fact about the SOURCES, which the aggregate
/// code holds, not about the vocabulary. This function answers only the
/// cross-tier question the vocabulary is responsible for.
#[must_use]
pub const fn blends_tiers(a: StatisticTier, b: StatisticTier) -> bool {
    !tiers_equal(a, b)
}

/// `a == b` as a `const fn`, since `PartialEq::eq` is not yet const for this
/// enum. Spelled out rather than derived so the one comparison the prohibition
/// rests on is visible.
const fn tiers_equal(a: StatisticTier, b: StatisticTier) -> bool {
    matches!(
        (a, b),
        (StatisticTier::RelayReported, StatisticTier::RelayReported)
            | (StatisticTier::SipnabMeasured, StatisticTier::SipnabMeasured)
            | (
                StatisticTier::EndpointReported,
                StatisticTier::EndpointReported
            )
    )
}

/// A statistic's presence, which is three states and not two (ST-S1, ST-S4).
///
/// Missing is not zero. A counter the relay reported as `0` is a fact; a key
/// nobody asked for is a different fact; a key asked for and refused is a
/// third. Collapsing any two of them tells an operator something false -- most
/// sharply, "unavailable" when the truth is a misspelled statistic name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StatisticValue {
    /// The source reported it, and this is the value it gave, uncoerced.
    /// rtpengine sends whole numbers as integers AND as strings (`uptime` is
    /// `"134"`), so the reading is kept as text and never parsed into a
    /// narrower type here.
    Counted(String),
    /// Nobody asked for it. On the wire: the key is ABSENT.
    NotAsked,
    /// Asked, and the source refused, with the code it gave. rtpproxy's `E68`
    /// (no such statistic) and `E50` (no such session) are different answers
    /// and only one is about the operator's call, so the code travels.
    Refused(String),
}

impl StatisticValue {
    /// Whether this value occupies a key on the wire at all.
    ///
    /// `Counted` does, including a counted zero. `NotAsked` and `Refused` do
    /// not: an absent key is how "not asked" reaches a reader, and a refusal is
    /// reported in a separate refusals list, named, rather than as a value.
    #[must_use]
    pub const fn is_present_on_the_wire(&self) -> bool {
        matches!(self, Self::Counted(_))
    }
}

/// One statistic with its tier attached -- the unit every surface renders
/// (ST-S3) and the form the tier rule (ST-S1) travels in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TieredStatistic {
    /// The source's own name, unaltered. `npkts_relayed`, not `packets_relayed`
    /// and not `Packets Relayed`: the key set is version-specific and
    /// translating it invents a vocabulary to maintain against every release.
    pub name: String,
    /// The value, in the three-state model.
    pub value: StatisticValue,
    /// Which of the three kinds of claim this is.
    pub tier: StatisticTier,
}

/// Tier a relay's OWN reported pairs (ST2).
///
/// Every pair a relay reports about itself is `relay_reported`, and every one
/// it reports is, by definition, a counted value -- the relay does not send a
/// key it is refusing. So each `(name, value)` becomes a `Counted` reading at
/// the `RelayReported` tier, the name kept exactly as the relay wrote it.
///
/// Takes plain pairs rather than a `ControlReply` so it stays portable: the
/// native caller destructures `ControlReply::Statistics(pairs)` and hands the
/// slice here. rtpengine's `statistics` and rtpproxy's `I`/`G` both reduce to
/// name/value pairs, so one adapter serves both.
#[must_use]
pub fn relay_reported(pairs: &[(String, String)]) -> Vec<TieredStatistic> {
    pairs
        .iter()
        .map(|(name, value)| TieredStatistic {
            name: name.clone(),
            value: StatisticValue::Counted(value.clone()),
            tier: StatisticTier::RelayReported,
        })
        .collect()
}

/// Look one statistic up by the source's own name.
///
/// Absent from the set is `NotAsked`, not a refusal: for a relay whose reply
/// carries everything it has (rtpengine's `statistics`), a name that is not
/// there is one this version does not report, and no error accompanied it. A
/// refusal -- an error code the relay returned -- is a different state that the
/// fetch path records as [`StatisticValue::Refused`], never synthesized here.
#[must_use]
pub fn lookup(stats: &[TieredStatistic], name: &str) -> StatisticValue {
    stats
        .iter()
        .find(|s| s.name == name)
        .map_or(StatisticValue::NotAsked, |s| s.value.clone())
}

/// The names a relay knows -- the answer to C3's "what can I even ask for?".
///
/// A name is known when the relay produced a value for it, which in this model
/// is exactly [`StatisticValue::is_present_on_the_wire`]: `Counted`, including a
/// counted zero. `NotAsked` is excluded because a name sipnab never asked about
/// is no evidence of what the relay has; `Refused` is excluded because
/// rtpproxy's `E68` means the relay does NOT have that name -- which is the
/// whole reason a probe answers C3 for a relay with no list command.
///
/// The set is sorted and deduplicated, so two relays' lists compare directly
/// and a caller reads a stable order regardless of the reply's order.
#[must_use]
pub fn known_names(stats: &[TieredStatistic]) -> Vec<String> {
    let mut names: Vec<String> = stats
        .iter()
        .filter(|s| s.value.is_present_on_the_wire())
        .map(|s| s.name.clone())
        .collect();
    names.sort();
    names.dedup();
    names
}

/// How a relay's set of known statistic names was established (C3).
///
/// The two are not the same claim, and the reply must not let them read as one.
/// rtpengine returns the whole set in a `statistics` reply, so the names are
/// `Listed` -- an enumeration. rtpproxy has no list command, so the set is
/// `Probed`: the names that did not return `E68` when asked. A name refused
/// today because the relay is momentarily busy is not the same as one this
/// build does not have, and a probed list is a weaker claim that says so.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NameSource {
    /// The relay enumerated them: rtpengine's `statistics` reply IS the list.
    Listed,
    /// Inferred by asking: the names that did not refuse (rtpproxy, no list
    /// command).
    Probed,
}

impl NameSource {
    /// One sentence stating how this list was determined, in an operator's
    /// words, so a probed set is never mistaken for a definitive enumeration.
    #[must_use]
    pub const fn how_determined(self) -> &'static str {
        match self {
            Self::Listed => "the relay listed these in a statistics reply",
            Self::Probed => {
                "these are the names that did not refuse when asked; a name refused \
                 today because the relay is busy is not the same as one this build lacks"
            }
        }
    }
}

/// One side of a tier comparison: a counted whole number at a named tier (C4).
///
/// The relay side carries the source's own key name (`totals.RTP.packets`) so
/// the reader knows which counter the relay's figure came from; sipnab's side
/// has no such name because it is a measurement, not a reported key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComparedFigure {
    /// The count, as a whole number. Both sides count RTP packets for one call.
    pub value: u64,
    /// The source's own name for the figure, where it has one.
    pub name: Option<String>,
    /// Which kind of claim this figure is.
    pub tier: StatisticTier,
}

/// The verdict of comparing two tiers -- a WORD, never a number (ST-S1).
///
/// The difference between a relay's count and sipnab's is not itself a
/// statistic: the two count different sockets over different windows, so
/// `relay - sipnab` describes nothing. The verdict says only whether they agree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ComparisonVerdict {
    /// The two counts are equal.
    Match,
    /// The two counts are not equal. An ordinary difference is not a relay
    /// fault, which is why the comparison carries a note and not just this word.
    Differ,
}

impl ComparisonVerdict {
    /// The wire spelling, matching ST-S3's example (`differ`).
    #[must_use]
    pub const fn as_wire_str(self) -> &'static str {
        match self {
            Self::Match => "match",
            Self::Differ => "differ",
        }
    }
}

/// A comparison of the SAME quantity across two tiers (ST7 / C4).
///
/// The one place two tiers appear in one answer, and it is a comparison, never
/// an aggregate: both figures are shown, both tiers are named, the verdict is a
/// word, and the note explains that an ordinary difference is not a relay fault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TierComparison {
    /// What the relay reported about itself.
    pub relay: ComparedFigure,
    /// What sipnab measured from the packets it captured.
    pub sipnab: ComparedFigure,
    /// Whether the two counts agree.
    pub verdict: ComparisonVerdict,
    /// Why a difference is ordinary, in the operator's words. Not decoration: a
    /// bare "differ" sends an operator to the relay first, and the usual cause
    /// is not there.
    pub note: String,
}

/// Compare a relay's reported count against sipnab's measured count (C4).
///
/// The verdict is exact: equal is a match, anything else differs. There is no
/// tolerance band, because a band would be a policy number sipnab does not
/// have; both raw counts travel and the operator judges the gap. The note
/// states the direction of a gap in prose and names its ordinary causes, but
/// never computes `relay - sipnab` as a value -- the cross-tier arithmetic
/// ST-S1's [`blends_tiers`] forbids stays out of the data, and the reader
/// subtracts the two shown figures themselves if they want to.
#[must_use]
pub fn compare_relay_and_sipnab(relay: ComparedFigure, sipnab: ComparedFigure) -> TierComparison {
    let verdict = if relay.value == sipnab.value {
        ComparisonVerdict::Match
    } else {
        ComparisonVerdict::Differ
    };
    let note = match verdict {
        ComparisonVerdict::Match => {
            format!("the relay and sipnab agree at {} RTP packets", relay.value)
        }
        // The note is direction-aware, because the ordinary causes are opposite.
        // sipnab BELOW the relay is an undercount -- packets that never reached
        // the capture point. sipnab ABOVE the relay is an overcount -- most
        // often a capture that sees BOTH sides of the relay hairpin, counting
        // each relayed packet twice (arriving, then leaving). A single note
        // listing only undercount causes would misexplain the second case,
        // which is the common one when capturing a relay's own segment.
        ComparisonVerdict::Differ if sipnab.value < relay.value => "sipnab counted fewer; it \
             measures only the RTP that reached its capture point, so an ordinary gap is not a \
             relay fault -- a capture on a mirror port under load undercounts, a relay restart \
             mid-call zeroes its counters, and a window that does not line up differs for \
             neither's fault. capture_health says whether this run dropped any packets."
            .to_string(),
        ComparisonVerdict::Differ => "the relay counted fewer; a capture that sees both sides of \
             a relay counts each packet more than once -- once arriving at the relay and once \
             leaving it -- so a point upstream AND downstream of the relay reads about twice \
             the relay's own count. A window that does not line up or a relay restart mid-call \
             also gaps them. To compare like for like, capture one leg, or read the relay's \
             per-stream counts."
            .to_string(),
    };
    TierComparison {
        relay,
        sipnab,
        verdict,
        note,
    }
}

/// The outcome of readying a C4 comparison, once each side's availability is
/// known (ST9: zero and absent are different answers).
///
/// A side is `Some(n)` when it produced a real count -- including a real zero --
/// and `None` when it produced nothing to compare: a relay that does not hold
/// the call, or a capture that measured no RTP for it. The three non-`Compared`
/// arms exist so an absent side is never rendered as `0` in a comparison that
/// then reads as a gap the relay must answer for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompareOutcome {
    /// Both sides produced a count; here is their comparison.
    Compared(TierComparison),
    /// The relay reported a count, but sipnab captured no RTP for this call --
    /// not measured zero, absent. The relay's figure is carried so a caller can
    /// say the call IS on the relay, sipnab just did not see its media.
    SipnabHasNoRtp {
        /// The relay's reported RTP packet count for the call.
        relay_value: u64,
    },
    /// sipnab measured the call, but the relay does not hold it. sipnab's count
    /// is carried; the relay side is absent, not zero.
    RelayDoesNotHoldCall {
        /// What sipnab measured for the call.
        sipnab_value: u64,
    },
    /// Neither side produced anything: nothing to compare, and no invented zero.
    NeitherSide,
}

/// Decide a C4 comparison from each side's availability (ST9).
///
/// `None` on a side means it produced nothing to compare -- a relay that does
/// not hold the call, or a capture with no RTP for it -- and is reported as
/// absent rather than coerced to `0`. Only when BOTH sides produced a count
/// (each `Some`, a real zero included) are they compared. This is where "zero
/// versus absent" is kept distinct: the caller passes `Some(0)` for a genuine
/// measured zero and `None` for "nothing here", and the two never collapse.
#[must_use]
pub fn ready_comparison(relay_value: Option<u64>, sipnab_value: Option<u64>) -> CompareOutcome {
    match (relay_value, sipnab_value) {
        (Some(relay), Some(sipnab)) => CompareOutcome::Compared(compare_relay_and_sipnab(
            ComparedFigure {
                value: relay,
                name: Some("totals.RTP.packets".to_string()),
                tier: StatisticTier::RelayReported,
            },
            ComparedFigure {
                value: sipnab,
                name: None,
                tier: StatisticTier::SipnabMeasured,
            },
        )),
        (Some(relay_value), None) => CompareOutcome::SipnabHasNoRtp { relay_value },
        (None, Some(sipnab_value)) => CompareOutcome::RelayDoesNotHoldCall { sipnab_value },
        (None, None) => CompareOutcome::NeitherSide,
    }
}

/// Who owns the problem when statistics could not be cleanly obtained.
///
/// The "whose problem" column of ST-S4's classification table, because it is
/// what tells an operator where to look. A `not_permitted` run is the
/// operator's own invocation; an `unreachable` relay is the network or the box;
/// a `refused` statistic is the request; a `suspect` answer is the answer
/// itself. A surface that reported the classification without this would make
/// an operator debug the relay for a mistake in their own command line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Responsibility {
    /// The operator's own invocation: no relay named, or no permit to transmit.
    Invocation,
    /// The network or the relay: asked, nothing came back.
    RelayOrNetwork,
    /// The request: the relay answered, and the answer was a refusal.
    Request,
    /// The answer: something arrived that cannot be trusted.
    Answer,
}

impl Responsibility {
    /// The wire name, so a surface that reports the classification can also say
    /// whose problem it is in a stable, machine-readable token.
    #[must_use]
    pub const fn as_wire_str(self) -> &'static str {
        match self {
            Self::Invocation => "invocation",
            Self::RelayOrNetwork => "relay_or_network",
            Self::Request => "request",
            Self::Answer => "answer",
        }
    }
}

/// What happened when a relay statistic was asked for and NOT cleanly obtained
/// (ST-S4).
///
/// The five classifications every surface reports identically. A clean success
/// is not here -- it is the statistics themselves; this enum is only the ways
/// an ask does not yield a trustworthy value, and they are kept distinct
/// because each sends an operator somewhere different.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StatisticsOutcome {
    /// sipnab was never given a relay to ask.
    NotConfigured,
    /// No transmit permit for this run -- a file-backed run, say, which must
    /// never be able to transmit to an address it read out of a capture.
    NotPermitted,
    /// Asked, and nothing came back. Indistinguishable, over UDP, from a down
    /// relay, a filtered port or a lost reply, so it must not claim any of them.
    Unreachable,
    /// Asked, and the relay said no, with the code it gave. The code travels in
    /// [`StatisticValue::Refused`]; this names the class.
    Refused,
    /// An answer arrived and something about it cannot be trusted -- a cookie
    /// that does not match, a counter that stepped backwards. The one that did
    /// not exist before ST-S4, because an answer that is present and wrong is
    /// the failure most likely to ship folded into "ok".
    Suspect,
}

impl StatisticsOutcome {
    /// Every classification, for a test that must cover them all.
    #[must_use]
    pub const fn all() -> [Self; 5] {
        [
            Self::NotConfigured,
            Self::NotPermitted,
            Self::Unreachable,
            Self::Refused,
            Self::Suspect,
        ]
    }

    /// The wire name, spelled once, matching ST-S4's table.
    #[must_use]
    pub const fn as_wire_str(self) -> &'static str {
        match self {
            Self::NotConfigured => "not_configured",
            Self::NotPermitted => "not_permitted",
            Self::Unreachable => "unreachable",
            Self::Refused => "refused",
            Self::Suspect => "suspect",
        }
    }

    /// Whose problem this is, so a surface can point the operator at it.
    #[must_use]
    pub const fn responsibility(self) -> Responsibility {
        match self {
            Self::NotConfigured | Self::NotPermitted => Responsibility::Invocation,
            Self::Unreachable => Responsibility::RelayOrNetwork,
            Self::Refused => Responsibility::Request,
            Self::Suspect => Responsibility::Answer,
        }
    }
}

/// One statistic resolved to a wire VALUE: it occupied a key, and this is what
/// a surface renders for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireValue {
    /// The source's own name, unaltered.
    pub name: String,
    /// The counted value, as the source gave it.
    pub value: String,
    /// Which of the three kinds of claim this is.
    pub tier: StatisticTier,
}

/// One statistic the source was asked for and REFUSED, with the code it gave.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireRefusal {
    /// The statistic's name, so a reader knows which ask was refused.
    pub name: String,
    /// The source's own refusal code -- `E68` and `E50` must not be collapsed.
    pub code: String,
}

/// Tiered statistics resolved for the wire (ST-S1's three-state rule).
///
/// Every surface applies the same rule, so it is single-sourced here rather
/// than reimplemented four times: a counted value occupies a key (including a
/// counted zero); a refusal is listed separately with its code, never as a
/// value; a not-asked statistic is absent from both -- omitted, never rendered
/// as a zero.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WireStatistics {
    /// The statistics that occupy a value key.
    pub present: Vec<WireValue>,
    /// The statistics asked for and refused.
    pub refusals: Vec<WireRefusal>,
}

/// Partition tiered statistics into present values and refusals, omitting the
/// not-asked (ST-S1).
///
/// This is the rule every surface follows. A consumer that iterated the
/// statistics itself and rendered each would be the fourth copy of the
/// three-state logic, and the one most likely to render a not-asked key as a
/// zero -- the exact failure ST-S1 forbids.
#[must_use]
pub fn resolve_for_wire(stats: &[TieredStatistic]) -> WireStatistics {
    let mut present = Vec::new();
    let mut refusals = Vec::new();
    for s in stats {
        match &s.value {
            StatisticValue::Counted(v) => present.push(WireValue {
                name: s.name.clone(),
                value: v.clone(),
                tier: s.tier,
            }),
            StatisticValue::Refused(code) => refusals.push(WireRefusal {
                name: s.name.clone(),
                code: code.clone(),
            }),
            // NotAsked occupies neither: omitted, never a zero.
            StatisticValue::NotAsked => {}
        }
    }
    WireStatistics { present, refusals }
}
