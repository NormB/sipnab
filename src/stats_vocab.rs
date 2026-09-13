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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
